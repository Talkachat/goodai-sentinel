"""Regression tests for review #4 (independent cowork audit)."""
import tempfile
from pathlib import Path
from sentinel.guardrail import Guardrail
from sentinel.events import Event
from sentinel.audit_async import AsyncAuditLog

POLICY = "policy/agent_guardrails.yaml"
def dec(g, **d): return g.decide(Event("agent","agent_action",d)).verdict

def test_encoded_traversal_denied():
    g = Guardrail(POLICY)
    for t in ["/workspace/%2e%2e/%2e%2e/etc/passwd", "/workspace/%2f%2f/x",
              "/workspace/%5c..%5c", "/workspace/app%00.py"]:
        assert dec(g, agent_id="coder-1", action="write:file", target=t) == "deny", t
    assert dec(g, agent_id="coder-1", action="write:file", target="/workspace/app.py") == "allow"

def test_null_byte_denied():
    g = Guardrail(POLICY)
    assert dec(g, agent_id="coder-1", action="write:file", target="/workspace/a\x00/etc/passwd") == "deny"

def test_backslash_and_case_traversal_denied():
    g = Guardrail(POLICY)
    assert dec(g, agent_id="coder-1", action="write:file", target="/workspace/..\\..\\etc/passwd") == "deny"
    assert dec(g, agent_id="coder-1", action="write:file", target="/WORKSPACE/../../etc/passwd") == "deny"

def test_write_after_close_rejected():
    a = AsyncAuditLog(Path(tempfile.mkdtemp())/"a.jsonl")
    assert a.close() is True                       # drained
    import pytest
    with pytest.raises(RuntimeError):
        a.write({"x": 1})

def test_close_reports_drain_status():
    a = AsyncAuditLog(Path(tempfile.mkdtemp())/"a.jsonl")
    a.write({"a": 1}); a.write({"b": 2})
    assert a.close() is True
    assert getattr(a, "drained_on_close", None) is True

def test_audit_store_injection_safe():
    from sentinel.audit_store import AuditStore
    st = AuditStore(str(Path(tempfile.mkdtemp())/"s.db"))
    st.write({"severity": "high'; DROP TABLE audit; --", "x": 1})
    assert st.count() == 1 and st.verify()         # parameterized -> table intact


def test_runtime_model_tamper_stops_job():
    import hashlib
    from integrations.distai.node_shield import NodeShield, ShieldError
    import pytest
    d = tempfile.mkdtemp(); mp = Path(d)/"m.gguf"; mp.write_bytes(b"GGUF"+b"\x00"*100)
    digest = hashlib.sha256(mp.read_bytes()).hexdigest()
    sh = NodeShield(coordinator_url="https://c.example.com:8443", node_id="n1",
                    models_dir=d, audit_path=str(Path(d)/"a.jsonl"))
    sh.manifest = {"models": {"m.gguf": digest}}
    assert sh.verify_model(mp)
    sh._integrity_tick()                      # prime baseline
    mp.write_bytes(b"HACKED"+b"\x00"*100)      # tamper after verification
    with pytest.raises(ShieldError):
        sh._integrity_tick()
