"""Demo: run Sentinel for a few seconds, simulate an attack + agent requests."""
import subprocess, time
from pathlib import Path
from sentinel.core import Sentinel

s = Sentinel(watch_paths=["/tmp/demo"], audit_path="/tmp/demo/audit.jsonl", warmup_s=0)
s.tick()                                                   # prime sensors

print("--- AI agent requests (ask-before-act) ---")
for agent, action, target in [
    ("coder-1",     "write:file", "/workspace/main.py"),
    ("coder-1",     "shell:run",  "/workspace/tests"),
    ("coder-1",     "shell:run",  "systemctl stop sentinel && rm -rf /"),
    ("untrusted-3", "write:file", "/tmp/x"),
    ("ops-1",       "deploy:prod-api", "v2.3"),
]:
    d = s.request(agent, action, target)
    print(f"{agent:12} {action:18} {target:38} -> {d.verdict.upper():16} {d.reason}")

print("\n--- Host monitoring: simulated suspicious activity (harmless) ---")
subprocess.Popen(["sh", "-c", "sleep 2"])                 # normal process
Path("/tmp/demo/authorized_keys").write_text("x")          # sensitive-file write
p = subprocess.Popen(["sh", "-c", "echo hi; sleep 1"])          # harmless
time.sleep(0.5)
for f in s.tick():
    print(f"[{f.severity}] {f.rule}: {f.reason[:90]}")
print("\nstats:", s.stats, "| audit chain valid:", s.audit.verify())
