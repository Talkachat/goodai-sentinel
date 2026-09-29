"""Guardrail: a policy engine that decides what an AI agent (or any automated actor)
is allowed to do. Deny-by-default, capability-scoped, rate-limited, budgeted, and
every decision is auditable.

Policy is plain YAML (policy/agent_guardrails.yaml) so non-programmers can review it.
"""
from __future__ import annotations
import fnmatch, re, threading, time
from functools import lru_cache
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
import yaml
from .events import Event
from .platform import norm_path
from .semantic import normalize
import posixpath, math

@dataclass
class Decision:
    verdict: str            # allow | deny | require_approval
    reason: str
    policy: str = ""

class Guardrail:
    def __init__(self, policy_path: str | Path):
        self._policy_path = Path(policy_path)
        self.policy = yaml.safe_load(self._policy_path.read_text())
        self._on_kill = []           # issuers register revoke_all here
        self._rate: dict[str, deque] = defaultdict(deque)
        self._spent: dict[str, float] = defaultdict(float)
        self._compiled = [(re.compile(p, re.I), name)
                          for name, p in self.policy.get("forbidden_patterns", {}).items()]
        self._agent_cache: dict[str, dict] = {}
        self._lock = threading.Lock()

    @staticmethod
    @lru_cache(maxsize=4096)
    def _glob(patterns: tuple) -> "re.Pattern":
        """Compile a list of globs into ONE alternation regex."""
        return re.compile("|".join(f"(?:{fnmatch.translate(norm_path(p))})" for p in patterns) or "(?!)")

    # -- helpers --
    def _agent(self, agent_id: str) -> dict:
        cfg = self._agent_cache.get(agent_id)
        if cfg is not None:
            return cfg
        agents = self.policy.get("agents", {})
        cfg = dict(self.policy.get("defaults", {}))
        for pat, over in agents.items():
            if fnmatch.fnmatch(agent_id, pat):
                cfg = {**cfg, **over}; break
        for k in ("capabilities", "deny_targets", "allow_targets", "require_approval"):
            cfg[k] = tuple(cfg.get(k) or ())
        self._agent_cache[agent_id] = cfg
        return cfg

    def _rate_ok(self, agent_id: str, limit: int, window: int) -> bool:
        q = self._rate[agent_id]; now = time.time()
        while q and now - q[0] > window:
            q.popleft()
        if len(q) >= limit:
            return False
        q.append(now); return True

    # -- main entry --
    def decide(self, ev: Event) -> Decision:
        if ev.kind != "agent_action":
            return Decision("allow", "not an agent action")
        with self._lock:
            return self._decide(ev)

    def reload(self):
        """Re-read the policy file at runtime (H3: editing YAML now takes effect)."""
        with self._lock:
            self.policy = yaml.safe_load(self._policy_path.read_text())
            self._agent_cache.clear()
            self._compiled = [(re.compile(p, re.I), name)
                              for name, p in self.policy.get("forbidden_patterns", {}).items()]
            if self.policy.get("kill_switch"):
                for cb in self._on_kill:
                    cb()

    def engage_kill_switch(self):
        with self._lock:
            self.policy["kill_switch"] = True
        for cb in self._on_kill:
            cb()

    @staticmethod
    def _canon(target: str) -> str:
        """Resolve . and .. textually (no filesystem touch) after normalising slashes.
        Collapses /workspace/../../etc -> /etc so containment checks can't be fooled."""
        t = norm_path(target)
        if not t:
            return t
        lead = "/" if t.startswith("/") else ""
        parts = []
        for seg in t.split("/"):
            if seg in ("", "."):
                continue
            if seg == "..":
                if parts:
                    parts.pop()
                continue
            parts.append(seg)
        return lead + "/".join(parts)

    # actions whose target is a filesystem path and must be present + contained
    FS_ACTIONS = ("write:", "read:file", "read:dir", "delete:", "run:", "shell:", "exec", "summarize:file", "deploy:")

    def _decide(self, ev: Event) -> Decision:
        d = ev.data
        agent, action = d.get("agent_id", "?"), d.get("action", "")
        raw_target = d.get("target", "")
        # Reject percent-encoded traversal/separators: a downstream consumer that URL-decodes
        # the target could turn %2e%2e / %2f into ../ and escape scope. We never decode; we deny.
        low = raw_target.lower()
        if any(tok in low for tok in ("%2e", "%2f", "%5c", "%00")):
            return Decision("deny", "percent-encoded path element in target", "encoded_target")
        if "\x00" in raw_target:
            return Decision("deny", "null byte in target", "null_target")
        target = self._canon(raw_target)
        if target.strip() == '':
            target = ''  # whitespace-only target counts as empty for the FS-action check
        # a filesystem action with no target cannot be scope-checked -> refuse
        if not target and any(action.startswith(a) or action == a for a in self.FS_ACTIONS):
            return Decision("deny", f"'{action}' requires a target", "empty_target")
        cfg = self._agent(agent)
        blob = f"{action} {target}"
        # Semantic layer: also test the DE-OBFUSCATED command, so quote-splitting (r"m"),
        # variable indirection (${x:-rm}) and ANSI-C hex/octal ($'\x72\x6d') can't smuggle
        # intent past literal patterns. Normalize the RAW target too, before slash-normalization
        # eats the backslashes that hex/octal escapes rely on.
        deob = normalize(blob)
        deob_raw = normalize(f"{action} {raw_target}")

        # 0. Kill switch
        if self.policy.get("kill_switch"):
            return Decision("deny", "global kill switch engaged", "kill_switch")

        # 1. Hard-forbidden patterns (self-modification, disabling defenses, destruction, exfil)
        for rx, name in self._compiled:
            if rx.search(blob):
                return Decision("deny", f"matches forbidden pattern '{name}'", "forbidden_patterns")
            if deob != blob and rx.search(deob):
                return Decision("deny", f"matches forbidden pattern '{name}' (de-obfuscated)", "forbidden_patterns")
            if deob_raw != deob and rx.search(deob_raw):
                return Decision("deny", f"matches forbidden pattern '{name}' (de-obfuscated)", "forbidden_patterns")

        # 2. Capability scoping: action must be in the agent's allowed set
        caps = cfg["capabilities"]
        if not self._glob(caps).match(action):
            return Decision("deny", f"'{action}' outside capabilities {caps}", "capabilities")

        # 3. Target scoping (paths / hosts)
        if cfg["deny_targets"] and self._glob(cfg["deny_targets"]).match(target):
            return Decision("deny", f"target '{target}' is in deny_targets", "deny_targets")
        allowed = cfg["allow_targets"]
        if allowed and target and not self._glob(allowed).match(target):
            return Decision("deny", f"target '{target}' not in allow_targets", "allow_targets")

        # 4. Rate limit
        rl = cfg.get("rate_limit", {})
        if rl and not self._rate_ok(agent, rl.get("max", 60), rl.get("window_s", 60)):
            return Decision("deny", f"rate limit {rl} exceeded", "rate_limit")

        # 5. Budget (cost, tokens, or any unit the caller reports)
        try:
            cost = float(d.get("cost", 0))
        except (TypeError, ValueError):
            return Decision("deny", "cost is not a number", "budget")
        if not math.isfinite(cost) or cost < 0:
            return Decision("deny", f"invalid cost {cost!r}", "budget")
        budget = cfg.get("budget")
        if budget is not None and self._spent[agent] + cost > budget:
            return Decision("deny", f"budget {budget} exhausted", "budget")
        # 6. Human-in-the-loop for irreversible / high-impact actions (budget not charged yet)
        ra = cfg["require_approval"]
        if ra and (self._glob(ra).match(action) or self._glob(ra).match(target)):
            return Decision("require_approval", f"'{action}' on '{target}' needs a human", "require_approval")

        self._spent[agent] += cost              # charged only for actions that proceed
        return Decision("allow", "within policy")
