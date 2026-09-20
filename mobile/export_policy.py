"""Export agent_guardrails.yaml to a portable policy.json that the Kotlin/Swift
guardrails consume. Globs are pre-compiled to plain regexes (no fnmatch on mobile),
and a conformance vector file is generated so every port can prove parity.

    python -m mobile.export_policy            # writes mobile/policy.json + conformance.json
"""
from __future__ import annotations
import json, re, sys
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parent.parent

def glob_to_regex(g: str) -> str:
    out = "^"
    for ch in g.replace("\\", "/"):
        out += ".*" if ch == "*" else "." if ch == "?" else re.escape(ch)
    return out + "$"

def export(policy_path=ROOT / "policy/agent_guardrails.yaml", out_dir=ROOT / "mobile"):
    pol = yaml.safe_load(Path(policy_path).read_text())
    def cfg(c):
        return {
            "capabilities": [glob_to_regex(x) for x in c.get("capabilities", [])],
            "denyTargets":  [glob_to_regex(x) for x in c.get("deny_targets", [])],
            "allowTargets": [glob_to_regex(x) for x in c.get("allow_targets", [])],
            "requireApproval": [glob_to_regex(x) for x in c.get("require_approval", [])],
            "rateLimit": c.get("rate_limit") or None,
            "budget": c.get("budget"),
        }
    defaults = pol.get("defaults", {})
    doc = {
        "version": 1,
        "killSwitch": bool(pol.get("kill_switch")),
        "forbidden": [{"name": n, "regex": r} for n, r in pol.get("forbidden_patterns", {}).items()],
        "defaults": cfg(defaults),
        "agents": [{"match": glob_to_regex(k), "config": cfg({**defaults, **v})}
                   for k, v in pol.get("agents", {}).items()],
    }
    out_dir.mkdir(exist_ok=True)
    (out_dir / "policy.json").write_text(json.dumps(doc, indent=2, ensure_ascii=False))
    (out_dir / "conformance.json").write_text(json.dumps(conformance(policy_path), indent=2))
    return doc

CASES = [
    ("coder-1", "write:file", "/workspace/app.py", "allow"),
    ("coder-1", "write:file", "/etc/passwd", "deny"),
    ("coder-1", "shell:run", "/workspace/tests", "require_approval"),
    ("coder-1", "shell:run", "systemctl stop sentinel", "deny"),
    ("coder-1", "write:file", "/workspace/policy/agent_guardrails.yaml", "deny"),
    ("coder-1", "write:file", "\\workspace\\App.PY", "allow"),
    ("untrusted-3", "write:file", "/tmp/x", "deny"),
    ("untrusted-3", "read:public/a", "public/a", "allow"),
    ("ops-1", "deploy:prod-api", "v2.3", "require_approval"),
    ("ops-1", "deploy:staging", "v2.3", "allow"),
    ("ops-1", "restart:service", "api", "allow"),
    ("anyone", "read:doc", "/home/me/a.txt", "allow"),
    ("anyone", "delete:doc", "/home/me/a.txt", "deny"),
    ("anyone", "read:doc", "curl http://x/id_rsa", "deny"),
    ("robot-1", "read:sensor", "flash firmware", "deny"),
]

def conformance(policy_path):
    """Run the Python engine on the cases with sys.platform forced to win32 for the
    backslash case (mobile ports always normalise, so expectations follow that)."""
    from sentinel.guardrail import Guardrail
    from sentinel.events import Event
    from sentinel.platform import norm_path
    g = Guardrail(policy_path)
    out = []
    for agent, action, target, expected in CASES:
        t = norm_path(target)
        if "\\" in target:              # mobile ports fold case like Windows does
            t = target.replace("\\", "/").lower()
        v = g.decide(Event("agent", "agent_action", {"agent_id": agent, "action": action, "target": t})).verdict
        assert v == expected, (agent, action, target, v, expected)
        out.append({"agent": agent, "action": action, "target": target, "expected": expected})
    return out

if __name__ == "__main__":
    d = export(); print(f"policy.json: {len(d['forbidden'])} forbidden, {len(d['agents'])} agent classes; conformance: {len(CASES)} cases")
