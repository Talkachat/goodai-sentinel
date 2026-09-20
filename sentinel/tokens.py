"""Capability tokens: ask the guardrail ONCE for a class of work, then check
locally in the hot loop. Token = scope + count + expiry, HMAC-signed by Sentinel.

Hot-loop cost: one HMAC compare + one counter decrement, no I/O, no locks
beyond a per-token atomic counter.
"""
from __future__ import annotations
import base64, hmac, hashlib, json, os, threading, time, fnmatch
from dataclasses import dataclass
from .events import Event
from .guardrail import Guardrail, Decision
from .platform import norm_path


@dataclass
class Grant:
    """Client-side handle; validate() is the hot-path call."""
    token: str
    agent_id: str
    action: str
    target: str
    remaining: int
    expires: float
    _secret: bytes
    _lock: threading.Lock
    _recheck: object = None          # callable(agent, action, target) -> verdict
    _revoked_gen: object = None       # callable() -> bool (True if this grant's generation was revoked)
    _authentic: object = None         # callable() -> bool (HMAC over claims)
    _tok_box: object = None

    def validate(self, action: str | None = None, target: str | None = None) -> bool:
        # 1. authenticity: the token must carry the issuer's HMAC over its own claims.
        if getattr(self, "_tok_box", None) is not None:
            self._tok_box[0] = self.token          # re-verify whatever token the handle now holds
        if self._authentic is not None and not self._authentic():
            return False
        if time.time() > self.expires or self.remaining <= 0 or self._revoked_gen():
            return False
        if action is not None and not fnmatch.fnmatch(action, self.action):
            return False
        if target is not None and self.target and not fnmatch.fnmatch(norm_path(target), norm_path(self.target)):
            return False
        # 2. concrete re-check: a wildcard grant may NOT reach a policy-denied target.
        if action is not None and self._recheck is not None:
            concrete = self._recheck(self.agent_id, action, target or "")
            if concrete != "allow":
                return False
        with self._lock:
            if self.remaining <= 0:
                return False
            self.remaining -= 1
        return True


class TokenIssuer:
    def __init__(self, guardrail: Guardrail, secret: bytes | None = None):
        self.guardrail = guardrail
        self.secret = secret or os.urandom(32)
        self.revoked: set[str] = set()
        self._live: dict[str, Grant] = {}
        self._lock = threading.Lock()
        self._generation = 0          # bumped by revoke_all(); grants below it are dead
        if hasattr(guardrail, "_on_kill"):
            guardrail._on_kill.append(self.revoke_all)
        self._grants_since_sweep = 0
        self._last_sweep = time.time()

    def _sweep(self):
        """Drop expired/exhausted grants (called under lock, every 100 grants)."""
        now = time.time()
        for tid in [t for t, g in self._live.items() if g.expires < now or g.remaining <= 0]:
            self._live.pop(tid, None)

    def _sign(self, payload: dict) -> str:
        body = base64.urlsafe_b64encode(json.dumps(payload, sort_keys=True).encode()).decode()
        mac = hmac.new(self.secret, body.encode(), hashlib.sha256).hexdigest()[:32]
        return f"{body}.{mac}"

    def verify(self, token: str) -> dict | None:
        try:
            body, mac = token.rsplit(".", 1)
        except ValueError:
            return None
        if not hmac.compare_digest(mac, hmac.new(self.secret, body.encode(), hashlib.sha256).hexdigest()[:32]):
            return None
        p = json.loads(base64.urlsafe_b64decode(body))
        if p["id"] in self.revoked or time.time() > p["exp"]:
            return None
        return p

    def grant(self, agent_id: str, action: str, target: str = "", count: int = 1000,
              ttl_s: float = 60.0, novelty: float = 0.0, **extra) -> tuple[Decision, Grant | None]:
        """Full guardrail decision on the *class* of work. Novelty shrinks the grant."""
        ev = Event("agent", "agent_action", {"agent_id": agent_id, "action": action,
                                             "target": target, "cost": extra.get("cost", 0)})
        d = self.guardrail.decide(ev)
        if d.verdict != "allow":
            return d, None
        # adaptive shaping: high novelty -> short, small grants
        scale = max(0.05, 1.0 - novelty)
        count, ttl_s = max(1, round(count * scale)), max(1.0, ttl_s * scale)
        tid = os.urandom(8).hex()
        payload = {"id": tid, "agent": agent_id, "action": action, "target": target,
                   "n": count, "exp": time.time() + ttl_s}
        token = self._sign(payload)          # "<b64body>.<mac>"
        gen_at_issue = self._generation
        secret = self.secret
        def _authentic(tok_ref):
            try:
                body, mac = tok_ref[0].rsplit(".", 1)
            except ValueError:
                return False
            good = hmac.new(secret, body.encode(), hashlib.sha256).hexdigest()[:32]
            return hmac.compare_digest(mac, good)
        tok_box = [token]                     # mutable ref so a swapped .token is re-verified
        g = Grant(token, agent_id, action, target, count, payload["exp"],
                  secret, threading.Lock(),
                  _recheck=self._recheck,
                  _revoked_gen=(lambda gi=gen_at_issue: self._generation != gi),
                  _authentic=(lambda: _authentic(tok_box)))
        g._tok_box = tok_box
        with self._lock:
            self._live[tid] = g
            self._grants_since_sweep += 1
            if self._grants_since_sweep >= 100 or time.time() - self._last_sweep > 1.0:
                self._grants_since_sweep = 0; self._last_sweep = time.time(); self._sweep()
        return d, g

    def revoke_all(self):
        """Kill-switch propagation: invalidate every outstanding grant at once."""
        with self._lock:
            self._generation += 1

    def _recheck(self, agent_id, action, target):
        from .events import Event
        return self.guardrail.decide(Event("agent", "agent_action",
            {"agent_id": agent_id, "action": action, "target": target})).verdict

    def revoke(self, agent_id: str | None = None, token_id: str | None = None):
        """Enforcement hook: kill all grants for an agent (or one token) instantly."""
        with self._lock:
            for tid, g in list(self._live.items()):
                if token_id == tid or (agent_id and g.agent_id == agent_id):
                    self.revoked.add(tid); g.remaining = 0; g.expires = 0
                    self._live.pop(tid, None)
