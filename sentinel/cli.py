import argparse, sys
from .core import Sentinel
from .platform import OS, DEFAULT_WATCH, is_admin

def main(argv=None):
    p = argparse.ArgumentParser("sentinel", description="GoodAI Sentinel — defensive monitor + AI-agent guardrail")
    p.add_argument("--watch", nargs="*", default=DEFAULT_WATCH, help="paths for file-integrity monitoring")
    p.add_argument("--interval", type=float, default=2.0)
    p.add_argument("--duration", type=float, default=None, help="seconds to run (default: forever)")
    p.add_argument("--warmup", type=float, default=60.0, help="baseline learning period")
    p.add_argument("--live", action="store_true", help="disable dry-run: actually isolate/terminate/block")
    p.add_argument("--autonomous", action="store_true", help="let critical findings act without approval")
    p.add_argument("--audit", default="./sentinel_audit.jsonl")
    p.add_argument("--watch-policy", action="store_true", help="hot-reload the policy file on change")
    a = p.parse_args(argv)
    s = Sentinel(watch_paths=a.watch, dry_run=not a.live, autonomous=a.autonomous,
                 warmup_s=a.warmup, audit_path=a.audit, watch_policy=a.watch_policy)
    print(f"Sentinel up on {OS}. dry_run={not a.live} autonomous={a.autonomous} watching={a.watch}", file=sys.stderr)
    if a.live and not is_admin():
        print("warning: --live without admin/root: network blocks and some isolations will fail", file=sys.stderr)
    try:
        s.run(a.interval, a.duration)
    except KeyboardInterrupt:
        pass
    print(f"stats: {s.stats}", file=sys.stderr)

if __name__ == "__main__":
    main()
