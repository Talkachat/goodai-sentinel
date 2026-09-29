"""Concurrency tests for capability tokens (review #5, P0: race conditions).

Proves that validate() is safe against concurrent revoke()/revoke_all() and that the
use-counter can never be over-spent under parallel load — the two concerns the review
raised about checks happening partly before the lock.
"""
import threading, time
from sentinel.guardrail import Guardrail
from sentinel.tokens import TokenIssuer

POLICY = "policy/agent_guardrails.yaml"

def _issuer():
    g = Guardrail(POLICY)
    g.policy["agents"]["coder-*"]["rate_limit"] = {"max": 10**9, "window_s": 60}
    g._agent_cache.clear()
    return g, TokenIssuer(g)

def test_no_use_succeeds_after_revoke():
    _, t = _issuer()
    leaks = 0
    for _ in range(100):
        _, grant = t.grant("coder-1", "read:file", "/workspace/*", count=1000)
        revoked_at = [None]; successes = []
        def hammer():
            ok = grant.validate("read:file", "/workspace/app.py")
            successes.append((time.perf_counter_ns(), ok))
        def revoke():
            time.sleep(0.00002); revoked_at[0] = time.perf_counter_ns()
            t.revoke(agent_id="coder-1")
        ths = [threading.Thread(target=hammer) for _ in range(16)] + [threading.Thread(target=revoke)]
        for th in ths: th.start()
        for th in ths: th.join()
        if revoked_at[0]:
            leaks += sum(1 for ts, ok in successes if ok and ts > revoked_at[0] + 50_000)
    assert leaks == 0, f"{leaks} uses succeeded after revoke"

def test_use_counter_never_overspent():
    _, t = _issuer()
    _, g = t.grant("coder-1", "read:file", "/workspace/*", count=100)
    ok = [0]; lock = threading.Lock()
    def use():
        if g.validate("read:file", "/workspace/a"):
            with lock: ok[0] += 1
    ths = [threading.Thread(target=use) for _ in range(500)]
    for th in ths: th.start()
    for th in ths: th.join()
    assert ok[0] == 100, f"expected exactly 100 successes, got {ok[0]}"

def test_revoke_all_stops_concurrent_use():
    g, t = _issuer()
    grants = [t.grant("coder-1", "read:file", "/workspace/*", count=1000)[1] for _ in range(5)]
    stop = threading.Event(); post = [0]; lock = threading.Lock()
    def hammer(gr):
        while not stop.is_set():
            gr.validate("read:file", "/workspace/a")
        # after revoke_all signalled, no further use may succeed
        if gr.validate("read:file", "/workspace/a"):
            with lock: post[0] += 1
    ths = [threading.Thread(target=hammer, args=(gr,)) for gr in grants]
    for th in ths: th.start()
    time.sleep(0.02); t.revoke_all(); stop.set()
    for th in ths: th.join()
    assert post[0] == 0
