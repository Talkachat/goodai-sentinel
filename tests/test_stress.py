"""Stress / performance regression tests (review P1). Smaller N than the full benchmark so
CI stays fast, but enough to catch a correctness-under-load or throughput regression."""
import threading
from bench.stress import bench_single, bench_concurrent, bench_audit

def test_single_thread_correct_and_fast():
    r = bench_single(n=5000)
    assert r["wrong_verdicts"] == 0
    assert r["decisions_per_sec"] > 5000          # generous floor; real is ~32k
    assert r["p99_us"] < 1000                      # p99 well under a millisecond

def test_concurrent_correctness_no_errors():
    r = bench_concurrent(threads=8, per_thread=3000)
    assert r["wrong_verdicts"] == 0                # verdicts correct under 8-way concurrency
    assert not r["errors"]                          # no crashes/exceptions

def test_audit_under_load_no_loss_and_masked():
    r = bench_audit(n=5000)
    assert r["dropped"] == 0                        # never drops audit data
    assert r["persisted"] + r["spilled"] >= 5000    # everything persisted (main or spill)
    assert r["chain_valid"] and r["masking_ok"]     # integrity + secret redaction hold under load
