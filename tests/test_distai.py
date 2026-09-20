import json, tempfile, time
from pathlib import Path
import pytest
from integrations.distai.manifest import gen_keypair, sign_manifest, verify_manifest, verify_model, sha256_file
from integrations.distai.node_shield import NodeShield, ShieldError
from integrations.distai.coordinator_guard import CoordinatorGuard

@pytest.fixture
def env():
    priv, pub = gen_keypair()
    with tempfile.TemporaryDirectory() as d:
        models = Path(d) / "models"; models.mkdir()
        gguf = models / "qwen.gguf"; gguf.write_bytes(b"GGUF" + b"\x01" * 1000)
        yield {"priv": priv, "pub": pub, "dir": Path(d), "models": models, "gguf": gguf}

def test_manifest_sign_verify_tamper_rollback_expiry(env):
    m = sign_manifest({"qwen.gguf": sha256_file(env["gguf"])}, env["priv"], version=5)
    assert verify_manifest(m, env["pub"])["version"] == 5
    bad = dict(m); bad["models"] = {"qwen.gguf": "0" * 64}
    with pytest.raises(ValueError): verify_manifest(bad, env["pub"])
    with pytest.raises(ValueError): verify_manifest(m, env["pub"], min_version=6)      # rollback
    old = sign_manifest({}, env["priv"], ttl_s=-1)
    with pytest.raises(ValueError): verify_manifest(old, env["pub"])
    assert verify_model(env["gguf"], m)
    env["gguf"].write_bytes(b"GGUF poisoned")
    with pytest.raises(ValueError): verify_model(env["gguf"], m)

def test_node_shield_end_to_end(env):
    sh = NodeShield("https://api.distai.net", "n1", env["models"], pubkey=env["pub"], audit_path=env["dir"]/"a.jsonl")
    sh.load_manifest(sign_manifest({"qwen.gguf": sha256_file(env["gguf"])}, env["priv"], version=1,
                                   blocklist=["1.2.3.4"]))
    assert sh.verify_model(env["gguf"]) and "1.2.3.4" in sh.blocked_ips
    good = {"job_id": "j1", "body": {"messages": [{"role": "user", "content": "hi"}], "max_tokens": 99999, "stream": True}}
    clean = sh.check_job(good)
    assert clean["max_tokens"] == 4096 and clean["stream"] is False
    with pytest.raises(ShieldError): sh.check_job({"body": {"messages": [{"role": "user", "content": "x"}], "tools": []}})
    with pytest.raises(ShieldError): sh.check_job({"body": {"messages": [{"role": "user", "content": [{"type": "image"}]}]}})
    with pytest.raises(ShieldError): sh.check_endpoint("https://evil.example/upload")
    sh.check_endpoint("https://api.distai.net/als/n1/jobs/poll"); sh.check_endpoint("http://127.0.0.1:8080/v1/chat")
    ok = {"choices": [{"message": {"content": "hello"}}]}
    assert sh.check_result(ok) == ok
    with pytest.raises(ShieldError):
        sh.check_result({"choices": [{"message": {"content": "key: sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789"}}]})
    # model swapped on disk between jobs -> job is now STOPPED (enforceable quarantine, review #4)
    env["gguf"].write_bytes(b"GGUF swapped")
    with pytest.raises(ShieldError):
        sh.check_job(good)
    f = sh.drain_findings()
    assert any(x["rule"] == "model_tamper_runtime" for x in f)
    assert sh.stats["denied"] >= 2 and sh.stats["leaks_blocked"] == 1
    with pytest.raises(ShieldError): sh.verify_model(env["gguf"])

def test_node_shield_refuses_without_pubkey(env):
    sh = NodeShield("https://api.distai.net", "n2", env["models"], pubkey=None, audit_path=env["dir"]/"b.jsonl")
    with pytest.raises(ShieldError): sh.load_manifest({})

def test_coordinator_guard_quarantine_and_fleet_blocklist(env):
    g = CoordinatorGuard(env["priv"], audit_path=env["dir"]/"c.jsonl")
    ok = {"status": "completed", "response": {"choices": [{"message": {"content": "answer"}}], "usage": {"completion_tokens": 10}}}
    assert g.may_dispatch("good")
    for i in range(20): g.observe_result("good", {}, {**ok, "response": {**ok["response"], "choices": [{"message": {"content": f"a{i}"}}]}}, 1.2)
    assert g.nodes["good"].status == "ok"
    # a node that answers instantly with the same output every time (fake/replay) + protocol abuse
    for i in range(20): g.observe_result("bad", {}, ok, 0.01)
    g.observe_violation("bad", "result for unassigned job")
    assert g.nodes["bad"].status == "quarantined" and not g.may_dispatch("bad")
    # fleet immune system: 3 nodes see the same destination -> signed blocklist
    for n in ("n1", "n2", "n3"):
        g.ingest_findings(n, [{"rule": "unexpected_endpoint", "severity": "critical", "reason": "attempted call to 5.6.7.8"}])
    assert "5.6.7.8" in g.blocklist
    m = g.signed_manifest({"qwen.gguf": "ab" * 32})
    assert "5.6.7.8" in verify_manifest(m, env["pub"])["blocklist"]
    assert g.sentinel.audit.verify()
