"""Orchestrator: wires sensors -> detector -> guardrail -> responder -> audit."""
from __future__ import annotations
import time
from pathlib import Path
from .sensors import ProcessSensor, NetworkSensor, FileIntegritySensor, AgentActionSensor
from .detector import Detector
from .guardrail import Guardrail, Decision
from .responder import Responder, AuditLog
from .audit_async import AsyncAuditLog
from .tokens import TokenIssuer
from .events import Event, Finding
from .platform import DEFAULT_WATCH
from .policy_watch import PolicyWatcher

HERE = Path(__file__).resolve().parent.parent

def _default_policy_path() -> str:
    """Prefer the source-tree policy; fall back to the packaged copy inside sentinel/."""
    src = HERE / "policy" / "agent_guardrails.yaml"
    if src.exists():
        return str(src)
    return str(Path(__file__).resolve().parent / "default_policy.yaml")


class Sentinel:
    def __init__(self, watch_paths=None, policy=None,
                 audit_path="./sentinel_audit.jsonl", dry_run=True, autonomous=False,
                 warmup_s=60.0, approver=None, notify=None, async_audit=False, watch_policy=False):
        watch_paths = DEFAULT_WATCH if watch_paths is None else watch_paths
        policy = _default_policy_path() if policy is None else policy
        self.agents = AgentActionSensor()
        self.sensors = [ProcessSensor(), NetworkSensor(), FileIntegritySensor(watch_paths), self.agents]
        self.detector = Detector()
        self.detector.baseline.warmup_s = warmup_s
        self.guardrail = Guardrail(policy)
        self.audit = AsyncAuditLog(audit_path) if async_audit else AuditLog(audit_path)
        self.tokens = TokenIssuer(self.guardrail)
        self.responder = Responder(self.audit, dry_run=dry_run, autonomous=autonomous,
                                   approver=approver, notify=notify)
        self.stats = {"events": 0, "findings": 0, "denied": 0, "approval": 0}
        self.policy_watcher = None
        if watch_policy:
            self.policy_watcher = PolicyWatcher(
                self.guardrail,
                on_reload=lambda p: self.audit.write({"policy_reloaded": str(p),
                                                      "kill_switch": self.guardrail.policy.get("kill_switch")}),
                on_error=lambda e: self.audit.write({"policy_reload_error": str(e)[:200]}),
            ).start()

    # ---- API for other AI agents: ask before you act ----
    def request(self, agent_id: str, action: str, target: str = "", **extra) -> Decision:
        ev = self.agents.submit(agent_id, action, target, **extra)
        dec = self.guardrail.decide(ev)
        self.stats["events"] += 1
        if dec.verdict == "deny":
            self.stats["denied"] += 1
            self.responder.handle(Finding(ev, f"guardrail:{dec.policy}", "high", dec.reason, 1.0, "alert"))
        elif dec.verdict == "require_approval":
            self.stats["approval"] += 1
            self.responder.handle(Finding(ev, "guardrail:approval", "medium", dec.reason, 0.5, "alert"))
        else:
            self.audit.write({"event": ev.data, "agent_event": ev.id, "decision": "allow"})
            self.detector.baseline.learn(ev)        # allowed agent behaviour becomes the norm
        # drain so the same event isn't re-scored by the poll loop
        list(self.agents.poll())
        return dec

    def grant(self, agent_id, action, target="", count=1000, ttl_s=60.0, novelty=None, **extra):
        """Tier 1: one guardrail decision -> local hot-path token."""
        if novelty is None:
            ev = Event("agent", "agent_action", {"agent_id": agent_id, "action": action, "target": target})
            b = self.detector.baseline
            novelty = b.score(ev) if (b.total and not b.warming()) else 0.0
        d, g = self.tokens.grant(agent_id, action, target, count, ttl_s, novelty, **extra)
        self.audit.write({"grant": {"agent": agent_id, "action": action, "target": target,
                                    "verdict": d.verdict, "count": g.remaining if g else 0,
                                    "novelty": round(novelty, 3)}})
        return d, g

    # ---- host monitoring ----
    def tick(self) -> list[Finding]:
        out = []
        for s in self.sensors:
            for ev in s.poll():
                self.stats["events"] += 1
                for f in self.detector.run(ev):
                    self.stats["findings"] += 1
                    self.responder.handle(f)
                    out.append(f)
        return out

    def run(self, interval: float = 2.0, duration: float | None = None):
        start = time.time()
        while duration is None or time.time() - start < duration:
            self.tick()
            time.sleep(interval)
