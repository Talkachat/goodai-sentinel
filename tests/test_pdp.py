import pytest
pytest.importorskip("fastapi"); pytest.importorskip("httpx")
from fastapi.testclient import TestClient
from pdp.server import app, _guardrail
from sentinel.guardrail import Guardrail
from sentinel.events import Event
client = TestClient(app)

def local(a, act, t=""):
    return Guardrail("policy/agent_guardrails.yaml").decide(
        Event("agent","agent_action",{"agent_id":a,"action":act,"target":t})).verdict
def remote(a, act, t=""):
    return client.post("/decide", json={"agent_id":a,"action":act,"target":t}).json()["verdict"]

def test_central_matches_local():
    for a,act,t in [("coder-1","write:file","/workspace/app.py"),
                    ("coder-1","shell:run","systemctl stop sentinel"),
                    ("coder-1","write:file","/workspace/../../etc/passwd"),
                    ("untrusted-9","write:file","/tmp/x"),
                    ("ops-1","deploy:prod-api","v2")]:
        assert remote(a,act,t) == local(a,act,t), (a,act,t)

def test_grant_over_http():
    r = client.post("/grant", json={"agent_id":"coder-1","action":"read:file","target":"/workspace/*","count":50}).json()
    assert r["verdict"] == "allow" and r["token"] and r["count"] == 50

def test_global_kill_switch():
    assert remote("coder-1","read:x","/workspace/a") == "allow"
    assert client.post("/kill").json()["kill_switch"] is True
    assert remote("coder-1","read:x","/workspace/a") == "deny"
    _guardrail.policy["kill_switch"] = False

def test_health():
    h = client.get("/health").json()
    assert h["ok"] and "stats" in h

def test_client_fail_closed_on_unreachable():
    from pdp.client import PDPClient
    c = PDPClient(url="http://127.0.0.1:59999", timeout=0.3)
    assert c.request("coder-1","shell:run","rm -rf /")["verdict"] == "deny"
    assert c.request("coder-1","read:file","/workspace/a")["verdict"] == "allow"
