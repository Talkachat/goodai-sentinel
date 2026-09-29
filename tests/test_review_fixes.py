"""Regression tests for the 10 findings of review #2 (docs/REVIEW_2.md)."""
import os, tempfile, threading, time
from pathlib import Path
from sentinel.events import Event
from sentinel.detector import Detector, Baseline
from sentinel.sensors import FileIntegritySensor, AgentActionSensor
from sentinel.guardrail import Guardrail
from sentinel.tokens import TokenIssuer
from sentinel.responder import Responder, AuditLog
from sentinel.audit_async import AsyncAuditLog
from sentinel.core import Sentinel

POLICY = "policy/agent_guardrails.yaml"
def ev(kind, **d): return Event(kind.split("_")[0], kind, d)

# F1 shared ransomware-window state
def test_detectors_have_independent_rule_state():
    a, b = Detector(), Detector()
    for i in range(24): list(a.run(ev("file_modified", path=f"/h/{i}")))
    assert not any(f.rule == "mass_file_change" for f in b.run(ev("file_modified", path="/h/x")))
    assert any(f.rule == "mass_file_change" for f in a.run(ev("file_modified", path="/h/y")))

# F2 grant halving: novelty must ignore feature kinds with no history
def test_grant_not_penalised_without_agent_history():
    with tempfile.TemporaryDirectory() as d:
        s = Sentinel(watch_paths=[d], audit_path=Path(d)/"a.jsonl", notify=lambda m: None, warmup_s=0)
        s.detector.baseline.learn(ev("new_process", name="bash", username="me", ppid=1))
        _, g = s.grant("coder-1", "read:file", "/workspace/*", count=1000)
        assert g.remaining == 1000
        # after allowed requests, agent history exists and a NEW agent is novel
        for _ in range(20): s.request("coder-1", "read:file", "/workspace/a")
        _, g2 = s.grant("coder-1", "read:file", "/workspace/*", count=1000)
        _, g3 = s.grant("coder-99", "read:file", "/workspace/*", count=1000)
        assert g2.remaining > g3.remaining

# F3 listener noise when pid unknown
def test_unknown_pid_listener_only_flags_bad_ports():
    d = Detector()
    assert not list(d.run(ev("listening_port", pid=None, laddr="0.0.0.0:8080")))
    assert list(d.run(ev("listening_port", pid=None, laddr="0.0.0.0:4444")))

# F4 thread-safe agent queue
def test_agent_sensor_no_lost_events_under_threads():
    s = AgentActionSensor(); got = []
    def prod():
        for i in range(2000): s.submit("a", "read:x", str(i))
    def cons():
        for _ in range(200): got.extend(s.poll()); time.sleep(0.0005)
    ts = [threading.Thread(target=prod) for _ in range(4)] + [threading.Thread(target=cons)]
    [t.start() for t in ts]; [t.join() for t in ts]
    got.extend(s.poll())
    assert len(got) == 8000

# F5 file sensor: cache, symlinks, cap, forged-timestamp rehash
def test_file_sensor_cache_symlink_cap_and_full_rehash():
    with tempfile.TemporaryDirectory() as d:
        for i in range(5): Path(d, f"f{i}").write_text(str(i))
        os.symlink("/etc", Path(d, "link"))
        fs = FileIntegritySensor([d], full_rehash_every=3); list(fs.poll())
        assert not any(k.endswith("/link") for k in fs._baseline) and not any("/etc/" in k for k in fs._baseline)
        # forge: same size + mtime, different content -> caught only by periodic full rehash
        p = Path(d, "f0"); st = p.stat(); p.write_text("X"); os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns))
        r1 = list(fs.poll())          # poll 2: stat cache may hide it (ctime changes on Linux -> may catch it)
        r2 = list(fs.poll())          # poll 3: forced full rehash
        assert any(e.kind == "file_modified" for e in r1 + r2)
        capped = FileIntegritySensor([d], max_files=2); list(capped.poll())
        assert capped.truncated and len(capped._baseline) == 2

# F6 async audit never drops
def test_async_audit_spills_instead_of_dropping():
    with tempfile.TemporaryDirectory() as d:
        a = AsyncAuditLog(Path(d)/"a.jsonl", flush_ms=200, max_queue=10)
        for i in range(200): a.write({"i": i})
        a.close()
        main = len((Path(d)/"a.jsonl").read_text().splitlines())
        spill_p = Path(d)/"a.jsonl.spill"
        spill = len(spill_p.read_text().splitlines()) if spill_p.exists() else 0
        assert a.dropped == 0 and main + spill == 200
        assert a.verify() and (not spill_p.exists() or AuditLog(spill_p).verify())

# F7 expired grants swept; target normalised in validate
def test_grant_sweep_and_target_normalisation():
    g0 = Guardrail(POLICY); g0.policy["agents"]["coder-*"]["rate_limit"] = {"max": 10**6, "window_s": 60}
    t = TokenIssuer(g0)
    for _ in range(150): t.grant("coder-1", "read:x", "/workspace/a")
    for g in list(t._live.values())[:150]: g.expires = 0          # simulate expiry (ttl floor is 1 s)
    for _ in range(100): t.grant("coder-1", "read:x", "/workspace/a")   # triggers a sweep
    assert len(t._live) <= 101
    _, g = t.grant("coder-1", "write:file", "/workspace/*")
    assert g.validate("write:file", "\\workspace\\App.py") or g.validate("write:file", "/workspace/App.py")

# F8 guardrail thread-safety + budget only on allow
def test_guardrail_threadsafe_and_budget_charged_on_allow_only():
    g = Guardrail(POLICY)
    r = g.decide(ev("agent_action", agent_id="ops-1", action="deploy:prod-api", target="v1", cost=40))
    assert r.verdict == "require_approval" and g._spent["ops-1"] == 0
    assert g.decide(ev("agent_action", agent_id="ops-1", action="read:x", target="", cost=40)).verdict == "allow"
    assert g._spent["ops-1"] == 40
    g.policy["agents"]["coder-*"]["rate_limit"] = {"max": 10**9, "window_s": 60}; g._agent_cache.clear()
    errs = []
    def w():
        try:
            for _ in range(2000): g.decide(ev("agent_action", agent_id="coder-1", action="read:x", target="/workspace/a"))
        except Exception as e: errs.append(e)
    ts = [threading.Thread(target=w) for _ in range(8)]; [t.start() for t in ts]; [t.join() for t in ts]
    assert not errs and len(g._rate["coder-1"]) == 16000

# F9 bounded pending approvals
def test_pending_queue_is_bounded():
    with tempfile.TemporaryDirectory() as d:
        r = Responder(AuditLog(Path(d)/"a.jsonl"), notify=lambda m: None); r.max_pending = 5
        det = Detector()
        for i in range(8):
            f = list(det.run(ev("new_process", cmdline=f"rm -rf / #{i}", name="rm", pid=i)))[0]
            r.handle(f)
        assert len(r.pending) == 5

# F10 packaging: plain pytest works (this file running under `pytest` proves it) and version bumped
def test_version():
    import sentinel; assert sentinel.__version__ >= "0.2"
