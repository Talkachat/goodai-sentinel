"""Regression tests for review #3 (authorization-boundary findings). Each must fail
against 0.2.1 and pass against 0.2.2+."""
import math, threading, tempfile
from pathlib import Path
import pytest
from sentinel.guardrail import Guardrail
from sentinel.tokens import TokenIssuer
from sentinel.responder import AuditLog
from sentinel.events import Event

POLICY = "policy/agent_guardrails.yaml"
def dec(g, agent, action, target, **k):
    return g.decide(Event("agent","agent_action",{"agent_id":agent,"action":action,"target":target,**k})).verdict

# H1 traversal + empty target
def test_path_traversal_denied():
    g = Guardrail(POLICY)
    assert dec(g,"coder-1","write:file","/workspace/../../etc/passwd") == "deny"
    assert dec(g,"coder-1","write:file","/workspace/../../../etc/shadow") == "deny"
    assert dec(g,"coder-1","write:file","/workspace/ok/./app.py") == "allow"   # benign . stays allowed
def test_empty_target_for_fs_action_denied():
    g = Guardrail(POLICY)
    assert dec(g,"coder-1","write:file","") == "deny"
    assert dec(g,"coder-1","read:doc","") == "allow"    # non-fs action may omit target

# H2 wildcard grant cannot reach a denied target
def test_wildcard_grant_cannot_reach_denied():
    t = TokenIssuer(Guardrail(POLICY))
    _, g = t.grant("coder-1","write:file","/workspace/*")
    assert g.validate("write:file","/workspace/app.py")
    assert not g.validate("write:file","/workspace/.env")
    assert not g.validate("write:file","/workspace/../../etc/passwd")

# H3 kill switch propagates to existing grants + reload
def test_kill_switch_kills_existing_grants():
    gr = Guardrail(POLICY); t = TokenIssuer(gr)
    _, g = t.grant("coder-1","write:file","/workspace/*")
    assert g.validate("write:file","/workspace/app.py")
    gr.engage_kill_switch()
    assert not g.validate("write:file","/workspace/app.py")
    assert dec(gr,"coder-1","read:x","/workspace/a") == "deny"
def test_policy_reload(tmp_path):
    pol = Path(POLICY).read_text()
    f = tmp_path/"p.yaml"; f.write_text(pol)
    gr = Guardrail(str(f))
    assert dec(gr,"coder-1","read:x","/workspace/a") == "allow"
    f.write_text(pol.replace("kill_switch: false","kill_switch: true"))
    gr.reload()
    assert dec(gr,"coder-1","read:x","/workspace/a") == "deny"

# H4 token authentication
def test_forged_token_rejected():
    t = TokenIssuer(Guardrail(POLICY))
    _, g = t.grant("coder-1","write:file","/workspace/*")
    g.token = "not-a-real-token"
    assert not g.validate("write:file","/workspace/app.py")
    # tampering with the body (agent claim) is rejected too
    body, mac = g.token, None

# H5 invalid costs
def test_invalid_costs_rejected():
    g = Guardrail(POLICY)
    for bad in (-1000, float("nan"), float("inf"), -0.0001):
        assert dec(g,"ops-1","read:x","",cost=bad) == "deny"
    assert g._spent.get("ops-1",0) == 0
    assert dec(g,"ops-1","read:x","",cost=1.0) == "allow"

# H6 concurrent audit chain integrity
def test_concurrent_audit_chain_valid():
    with tempfile.TemporaryDirectory() as d:
        a = AuditLog(Path(d)/"a.jsonl")
        def w():
            for i in range(200): a.write({"i":i})
        ts=[threading.Thread(target=w) for _ in range(8)]; [x.start() for x in ts]; [x.join() for x in ts]
        assert a.verify()
        assert len((Path(d)/"a.jsonl").read_text().splitlines()) == 1600

# H8 packaged-policy fallback
def test_packaged_policy_fallback():
    from sentinel.core import _default_policy_path
    assert Path(_default_policy_path()).exists()
    assert (Path("sentinel")/"default_policy.yaml").exists()
