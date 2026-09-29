"""Run the independent enforcer from the command line:
    python -m enforcement --duration 60          # observe only (dry-run)
    python -m enforcement --live                  # actually freeze denied processes
"""
import argparse, sys
from .enforcer import IndependentEnforcer

def main(argv=None):
    p = argparse.ArgumentParser("enforcement", description="GoodAI Sentinel — independent OS-level enforcer")
    p.add_argument("--policy", default="policy/agent_guardrails.yaml")
    p.add_argument("--audit", default="./enforcer_audit.jsonl")
    p.add_argument("--interval", type=float, default=2.0)
    p.add_argument("--duration", type=float, default=None)
    p.add_argument("--live", action="store_true", help="freeze denied processes (default: observe only)")
    a = p.parse_args(argv)
    e = IndependentEnforcer(a.policy, audit_path=a.audit, dry_run=not a.live,
                            on_deny=lambda t, d: print(f"[DENY] {t[:80]} ({d.policy})"))
    print(f"Independent enforcer up. live={a.live}. Watching OS activity as '{e.stats and 'os-activity'}'.")
    try:
        e.run(a.interval, a.duration)
    except KeyboardInterrupt:
        pass
    print(f"stats: {e.stats}")

if __name__ == "__main__":
    main()
