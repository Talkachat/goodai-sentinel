"""Detection = explicit rules (high precision) + behavioral baseline (catches the unknown).

The baseline is a lightweight per-feature frequency model: anything the host has never
done before scores high. It learns during `warmup` seconds and keeps learning from
events that were NOT flagged, so it adapts without learning from attacks.
"""
from __future__ import annotations
import math, re, time
from collections import Counter, defaultdict
from typing import Callable, Iterable, Iterator
from .events import Event, Finding

Rule = Callable[[Event], "Finding | None"]

# ---------- Rules: deliberately readable so anyone can audit/extend them ----------

from .platform import (SUSPICIOUS_CMD, PRIVESC_CMD, SENSITIVE_PATHS, TEMP_DIRS,
                       norm_path, OS)
SUSPICIOUS_PORTS = {4444, 1337, 31337, 6667, 9001, 5555}
PRIVATE_NET = re.compile(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|::1$|fe80:)")


def rule_dangerous_command(ev: Event):
    if ev.kind != "new_process":
        return None
    cmd = ev.data.get("cmdline", "") or ""
    if SUSPICIOUS_CMD.search(cmd):
        return Finding(ev, "dangerous_command", "critical",
                       f"Destructive/exploit-style command: {cmd[:120]}", 0.95, "terminate")
    if PRIVESC_CMD.search(cmd):
        return Finding(ev, "privilege_escalation", "high",
                       f"Privilege escalation attempt: {cmd[:120]}", 0.8, "alert")
    return None


def rule_temp_exec(ev: Event):
    if ev.kind != "new_process":
        return None
    exe = norm_path(ev.data.get("exe") or "").lower()
    if any(t in exe for t in TEMP_DIRS):
        return Finding(ev, "exec_from_temp", "high",
                       f"Binary executed from temp dir: {exe}", 0.85, "isolate")
    return None


def rule_sensitive_file(ev: Event):
    if ev.kind not in ("file_modified", "file_created", "file_deleted"):
        return None
    path = norm_path(ev.data.get("path", "")).lower()
    if any(s.lower() in path for s in SENSITIVE_PATHS):
        sev = "critical" if ev.kind == "file_deleted" else "high"
        return Finding(ev, "sensitive_file_change", sev,
                       f"{ev.kind} on sensitive path {path}", 0.9, "alert")
    return None


def rule_suspicious_network(ev: Event):
    if ev.kind == "outbound_conn":
        rport, rip = ev.data.get("rport"), ev.data.get("rip") or ""
        if rport in SUSPICIOUS_PORTS:
            return Finding(ev, "c2_port", "high",
                           f"Outbound to known C2/backdoor port {rport} ({rip})", 0.8, "block")
    if ev.kind == "listening_port":
        pid = ev.data.get("pid")
        port = int((ev.data.get("laddr") or ":0").rsplit(":", 1)[-1])
        # pid is None for every socket when unprivileged (macOS especially) -> only flag known-bad ports then
        if port in SUSPICIOUS_PORTS or (port > 1024 and pid is not None and pid <= 0):
            return Finding(ev, "unexpected_listener", "medium",
                           f"New listener on port {port}", 0.6, "alert")
    return None


def rule_mass_file_change(state: dict) -> Rule:
    """Ransomware signature: many files modified in a short window."""
    def _rule(ev: Event):
        if ev.kind not in ("file_modified", "file_created"):
            return None
        now = time.time()
        win = state.setdefault("win", [])
        win.append(now)
        state["win"] = win = [t for t in win if now - t < 10]
        if len(win) >= 25 and not state.get("fired"):
            state["fired"] = True
            return Finding(ev, "mass_file_change", "critical",
                           f"{len(win)} files changed in 10s (possible ransomware)", 0.9, "isolate")
        if len(win) < 5:
            state["fired"] = False
        return None
    return _rule


def rule_agent_action(ev: Event):
    """Agent actions get *scored* here; allow/deny is decided by the Guardrail."""
    if ev.kind != "agent_action":
        return None
    a = ev.data.get("action", ""); t = ev.data.get("target", "")
    blob = f"{a} {t}"
    if SUSPICIOUS_CMD.search(blob) or any(s.lower() in norm_path(t).lower() for s in SENSITIVE_PATHS):
        return Finding(ev, "agent_dangerous_action", "critical",
                       f"Agent {ev.data.get('agent_id')} proposed: {blob[:120]}", 0.95, "block")
    return None


def default_rules() -> list[Rule]:
    """Fresh stateful rules per Detector (no shared state between instances)."""
    from .rules_2026_09 import report_rules
    return [rule_dangerous_command, rule_temp_exec, rule_sensitive_file,
            rule_suspicious_network, rule_mass_file_change({}), rule_agent_action, *report_rules()]

DEFAULT_RULES = default_rules()   # kept for backwards compatibility; prefer default_rules()


# ---------- Behavioral baseline ----------

class Baseline:
    """Novelty scoring: score = 1 - p(feature seen before), averaged over features.
    Cheap, explainable, no training data needed — a good default before you add ML."""
    def __init__(self, warmup_s: float = 60.0, threshold: float = 0.75):
        self.counts: dict[str, Counter] = defaultdict(Counter)
        self.total: Counter = Counter()
        self.start = time.time()
        self.warmup_s = warmup_s
        self.threshold = threshold

    @staticmethod
    def features(ev: Event) -> dict[str, str]:
        d = ev.data
        if ev.kind == "new_process":
            return {"proc.name": str(d.get("name")), "proc.user": str(d.get("username")),
                    "proc.parent": str(d.get("ppid"))}
        if ev.kind == "outbound_conn":
            rip = d.get("rip") or ""
            return {"net.dst_private": str(bool(PRIVATE_NET.match(rip))),
                    "net.rport": str(d.get("rport")), "net.pid": str(d.get("pid"))}
        if ev.kind == "listening_port":
            return {"net.listen": str(d.get("laddr"))}
        if ev.kind.startswith("file_"):
            return {"file.dir": str(d.get("path", "")).rsplit("/", 1)[0]}
        if ev.kind == "agent_action":
            return {"agent.id": str(d.get("agent_id")), "agent.action": str(d.get("action"))[:40]}
        return {}

    def warming(self) -> bool:
        return time.time() - self.start < self.warmup_s

    def score(self, ev: Event) -> float:
        """Novelty over features whose *kind* has history. Unseen feature kinds contribute
        nothing (not 0.5), so a first agent grant after host-only warm-up is not penalised."""
        feats = self.features(ev)
        s = []
        for k, v in feats.items():
            tot = self.total[k]
            if tot == 0:
                continue
            p = (self.counts[k][v] + 0.5) / (tot + 1.0)          # smoothed frequency
            s.append(1.0 - p)
        return sum(s) / len(s) if s else 0.0

    def learn(self, ev: Event):
        for k, v in self.features(ev).items():
            self.counts[k][v] += 1
            self.total[k] += 1


class Detector:
    def __init__(self, rules: Iterable[Rule] | None = None, baseline: Baseline | None = None):
        self.rules = list(rules) if rules is not None else default_rules()
        self.baseline = baseline or Baseline()

    def run(self, ev: Event) -> Iterator[Finding]:
        flagged = False
        for rule in self.rules:
            f = rule(ev)
            if f:
                flagged = True
                yield f
        if not flagged:
            if not self.baseline.warming():
                s = self.baseline.score(ev)
                if s >= self.baseline.threshold and self.baseline.total:
                    flagged = True
                    yield Finding(ev, "behavioral_anomaly", "medium",
                                  f"Never-before-seen behavior ({ev.kind}), novelty={s:.2f}",
                                  s, "alert")
        if not flagged:
            self.baseline.learn(ev)    # only learn from benign traffic
