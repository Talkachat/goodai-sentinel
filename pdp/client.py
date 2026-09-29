"""Thin PEP client. Fails CLOSED for irreversible actions if the PDP is unreachable."""
from __future__ import annotations
import httpx
IRREVERSIBLE = ("delete:", "deploy:", "pay:", "send:", "shell:", "write:")

class PDPClient:
    def __init__(self, url="http://localhost:8080", node_id="node-1", token: str | None = None, timeout=2.0):
        self.url = url.rstrip("/"); self.node_id = node_id; self.timeout = timeout
        self.headers = {"X-Node-Token": token} if token else {}
    def request(self, agent_id, action, target="", cost=0.0) -> dict:
        try:
            r = httpx.post(f"{self.url}/decide", json={"agent_id": agent_id, "action": action,
                          "target": target, "cost": cost, "node_id": self.node_id},
                          headers=self.headers, timeout=self.timeout)
            r.raise_for_status(); return r.json()
        except Exception as e:
            fc = any(action.startswith(p) for p in IRREVERSIBLE)
            return {"verdict": "deny" if fc else "allow",
                    "reason": f"PDP unreachable ({e}); failed {'closed' if fc else 'open'}",
                    "policy": "pdp_unreachable"}
    def grant(self, agent_id, action, target="", count=1000, ttl_s=60.0) -> dict:
        r = httpx.post(f"{self.url}/grant", json={"agent_id": agent_id, "action": action,
                      "target": target, "count": count, "ttl_s": ttl_s, "node_id": self.node_id},
                      headers=self.headers, timeout=self.timeout)
        return r.json()
