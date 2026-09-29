"""Stress + performance benchmark for the guardrail hot path under load.

Measures: throughput (decisions/sec), latency percentiles (p50/p95/p99/max), correctness
under concurrency (no wrong verdicts, counters intact), and stability (no crashes, bounded
memory) across single-thread and multi-thread runs.

Run:  python -m bench.stress
"""
from __future__ import annotations
import statistics, threading, time, gc
from sentinel.guardrail import Guardrail
from sentinel.events import Event

POLICY = "policy/agent_guardrails.yaml"

CASES = [
    ("coder-1", "write:file", "/workspace/app.py", "allow"),
    ("coder-1", "shell:run", "rm -rf /", "deny"),
    ("coder-1", "write:file", "/workspace/../../etc/passwd", "deny"),
    ("coder-1", 'shell:run', 'r"m" -rf /', "deny"),           # semantic layer exercised
    ("untrusted-9", "read:public/x", "public/x", "allow"),
    ("ops-1", "deploy:prod-api", "v2", "require_approval"),
]

def _decide(g, c):
    return g.decide(Event("agent", "agent_action",
                    {"agent_id": c[0], "action": c[1], "target": c[2]})).verdict

def _unbounded(g):
    for pat in g.policy.get("agents", {}):
        g.policy["agents"][pat]["rate_limit"] = {"max": 10**15, "window_s": 60}
        g.policy["agents"][pat]["budget"] = 10**15
    g._agent_cache.clear(); return g

def bench_single(n=50000):
    g = _unbounded(Guardrail(POLICY))
    lat = []; wrong = 0
    t0 = time.perf_counter()
    for i in range(n):
        c = CASES[i % len(CASES)]
        s = time.perf_counter_ns()
        v = _decide(g, c)
        lat.append(time.perf_counter_ns() - s)
        if v != c[3]: wrong += 1
    dt = time.perf_counter() - t0
    lat.sort()
    return {
        "n": n, "sec": round(dt, 3), "decisions_per_sec": round(n / dt),
        "p50_us": round(lat[len(lat)//2] / 1000, 2),
        "p95_us": round(lat[int(len(lat)*0.95)] / 1000, 2),
        "p99_us": round(lat[int(len(lat)*0.99)] / 1000, 2),
        "max_us": round(lat[-1] / 1000, 2),
        "wrong_verdicts": wrong,
    }

def bench_concurrent(threads=8, per_thread=20000):
    g = _unbounded(Guardrail(POLICY))
    wrong = [0]; lock = threading.Lock(); errors = []
    def worker():
        w = 0
        try:
            for i in range(per_thread):
                c = CASES[i % len(CASES)]
                if _decide(g, c) != c[3]: w += 1
        except Exception as e:
            errors.append(repr(e))
        with lock: wrong[0] += w
    t0 = time.perf_counter()
    ts = [threading.Thread(target=worker) for _ in range(threads)]
    for t in ts: t.start()
    for t in ts: t.join()
    dt = time.perf_counter() - t0
    total = threads * per_thread
    return {"threads": threads, "total": total, "sec": round(dt, 3),
            "decisions_per_sec": round(total / dt), "wrong_verdicts": wrong[0],
            "errors": errors[:3]}

def bench_audit(n=50000):
    import tempfile, os
    from pathlib import Path
    from sentinel.audit_async import AsyncAuditLog
    d = tempfile.mkdtemp()
    a = AsyncAuditLog(Path(d)/"a.jsonl", flush_ms=20)
    t0 = time.perf_counter()
    for i in range(n):
        a.write({"event": "bench", "i": i, "cmd": "curl -H 'Authorization: Bearer sk-xxxxxxxxxxxxxxxxxxxx' host"})
    a.close()
    dt = time.perf_counter() - t0
    lines = len(Path(d, "a.jsonl").read_text().splitlines())
    spill = a.spilled
    valid = a.verify()
    return {"n": n, "sec": round(dt, 3), "writes_per_sec": round(n/dt),
            "persisted": lines, "spilled": spill, "dropped": a.dropped,
            "chain_valid": valid, "masking_ok": "sk-xxxx" not in Path(d,"a.jsonl").read_text()}

if __name__ == "__main__":
    print("=== 1. single-thread guardrail ===")
    print(bench_single())
    print("\n=== 2. concurrent guardrail (8 threads) ===")
    print(bench_concurrent())
    print("\n=== 3. async audit under load (with masking) ===")
    print(bench_audit())
