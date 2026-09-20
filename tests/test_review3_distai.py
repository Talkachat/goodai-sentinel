import pytest
crypto = pytest.importorskip("cryptography")
import tempfile
from pathlib import Path

def _shield(tmp):
    from integrations.distai.node_shield import NodeShield, ShieldError
    return NodeShield(coordinator_url="https://coord.example.com:8443", node_id="node-1",
                      models_dir=tmp, audit_path=str(Path(tmp)/"a.jsonl")), ShieldError

def test_max_tokens_must_be_positive(tmp_path):
    sh, Err = _shield(str(tmp_path))
    with pytest.raises(Err):
        sh.check_job({"body": {"messages":[{"role":"user","content":"hi"}], "max_tokens": -1}})
    ok = sh.check_job({"body": {"messages":[{"role":"user","content":"hi"}], "max_tokens": 100}})
    assert ok["max_tokens"] == 100

def test_endpoint_with_port(tmp_path):
    sh, Err = _shield(str(tmp_path))
    sh.check_endpoint("https://coord.example.com:8443/pull")   # same host, explicit port -> ok
    with pytest.raises(Err):
        sh.check_endpoint("https://evil.example.com/x")

def test_upload_denied_is_enforced(tmp_path):
    sh, Err = _shield(str(tmp_path))
    sh.sentinel.guardrail.engage_kill_switch()
    with pytest.raises(Err):
        sh.check_result({"choices":[{"message":{"content":"fine"}}]})
