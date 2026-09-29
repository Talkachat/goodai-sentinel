"""Central policy service. Run: uvicorn pdp.server:app --host 0.0.0.0 --port 8080"""
from __future__ import annotations
import hmac, hashlib, os, time
from pathlib import Path
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel
from sentinel.guardrail import Guardrail
from sentinel.tokens import TokenIssuer
from sentinel.events import Event
from sentinel.responder import AuditLog

POLICY = os.environ.get("PDP_POLICY", str(Path(__file__).resolve().parent.parent / "policy/agent_guardrails.yaml"))
AUDIT = os.environ.get("PDP_AUDIT", "./pdp_audit.jsonl")
PDP_KEY = os.environ.get("PDP_KEY", "").encode() or os.urandom(32)

app = FastAPI(title="GoodAI Sentinel — Policy Decision Point", version="0.1.0")
_guardrail = Guardrail(POLICY)
_issuer = TokenIssuer(_guardrail)
_audit = AuditLog(AUDIT)
_stats = {"decide": 0, "allow": 0, "deny": 0, "require_approval": 0, "grant": 0}

class DecideReq(BaseModel):
    agent_id: str; action: str; target: str = ""; cost: float = 0.0; node_id: str = "unknown"

class GrantReq(BaseModel):
    agent_id: str; action: str; target: str = ""; count: int = 1000; ttl_s: float = 60.0; node_id: str = "unknown"

def _auth(node_token: str | None):
    if not os.environ.get("PDP_KEY"):
        return
    if not node_token:
        raise HTTPException(401, "missing X-Node-Token")
    good = hmac.new(PDP_KEY, b"node", hashlib.sha256).hexdigest()
    if not hmac.compare_digest(node_token, good):
        raise HTTPException(403, "bad node token")

@app.post("/decide")
def decide(req: DecideReq, x_node_token: str | None = Header(default=None)):
    _auth(x_node_token); _stats["decide"] += 1
    d = _guardrail.decide(Event("agent", "agent_action", {
        "agent_id": req.agent_id, "action": req.action, "target": req.target, "cost": req.cost}))
    _stats[d.verdict] = _stats.get(d.verdict, 0) + 1
    _audit.write({"node": req.node_id, "agent": req.agent_id, "action": req.action,
                  "target": req.target, "verdict": d.verdict, "policy": d.policy})
    return {"verdict": d.verdict, "reason": d.reason, "policy": d.policy}

@app.post("/grant")
def grant(req: GrantReq, x_node_token: str | None = Header(default=None)):
    _auth(x_node_token); _stats["grant"] += 1
    d, g = _issuer.grant(req.agent_id, req.action, req.target, req.count, req.ttl_s)
    if not g:
        _audit.write({"node": req.node_id, "agent": req.agent_id, "grant": "denied", "reason": d.reason})
        return {"verdict": d.verdict, "reason": d.reason, "token": None}
    _audit.write({"node": req.node_id, "agent": req.agent_id, "grant": "issued", "count": g.remaining})
    return {"verdict": "allow", "token": g.token, "count": g.remaining, "expires": g.expires}

@app.post("/kill")
def kill(x_node_token: str | None = Header(default=None)):
    _auth(x_node_token); _guardrail.engage_kill_switch()
    _audit.write({"event": "GLOBAL_KILL_SWITCH_ENGAGED", "ts": time.time()})
    return {"kill_switch": True}

@app.post("/reload")
def reload(x_node_token: str | None = Header(default=None)):
    _auth(x_node_token); _guardrail.reload()
    _audit.write({"event": "policy_reloaded", "kill_switch": _guardrail.policy.get("kill_switch")})
    return {"reloaded": True, "kill_switch": _guardrail.policy.get("kill_switch")}

@app.get("/health")
def health():
    return {"ok": True, "kill_switch": _guardrail.policy.get("kill_switch"), "stats": _stats,
            "audit_valid": _audit.verify()}
