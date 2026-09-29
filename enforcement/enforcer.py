"""IndependentEnforcer: observe OS events, apply the guardrail, act on denials —
without the agent's cooperation.

It reuses the project's existing ProcessSensor/NetworkSensor (already read-only OS
observers) and the existing Guardrail. The novelty is *who asks*: here the enforcer asks
on the OS's behalf, not the agent's.
"""
from __future__ import annotations
import os, signal, time
from .mapper import process_to_action, connection_to_action, OS_AGENT_ID
from sentinel.guardrail import Guardrail
from sentinel.events import Event
from sentinel.sensors import ProcessSensor, NetworkSensor
from sentinel.responder import AuditLog

try:
    import psutil
except ImportError:
    psutil = None


class IndependentEnforcer:
    def __init__(self, policy_path, audit_path="./enforcer_audit.jsonl",
                 dry_run=True, on_deny=None):
        self.guardrail = Guardrail(policy_path)
        self.audit = AuditLog(audit_path)
        self.dry_run = dry_run
        self.on_deny = on_deny or (lambda ev, dec: None)
        self.proc = ProcessSensor()
        self.net = NetworkSensor()
        self.stats = {"observed": 0, "denied": 0, "acted": 0}
        self.audit.write({"event": "enforcer_started", "dry_run": dry_run, "os_agent": OS_AGENT_ID})

    def _judge(self, action: str, target: str, pid=None):
        """Ask the guardrail as the OS, not as a cooperating agent."""
        self.stats["observed"] += 1
        dec = self.guardrail.decide(Event("agent", "agent_action",
              {"agent_id": OS_AGENT_ID, "action": action, "target": target}))
        if dec.verdict == "deny":
            self.stats["denied"] += 1
            self.audit.write({"enforced": True, "action": action, "target": target,
                              "verdict": dec.verdict, "policy": dec.policy, "pid": pid,
                              "acted": (not self.dry_run)})
            self.on_deny(target, dec)
            if not self.dry_run and pid:
                self._stop(pid)
        return dec

    def _stop(self, pid):
        """Independent action: stop a process the agent never declared. Freeze (reversible),
        preserving forensics — mirrors the responder's isolate step."""
        if psutil is None:
            return
        try:
            psutil.Process(pid).suspend()
            self.stats["acted"] += 1
        except Exception as e:
            self.audit.write({"enforce_action_failed": str(e), "pid": pid})

    def tick(self):
        for ev in self.proc.poll():
            if ev.kind == "new_process":
                action, target = process_to_action(ev.data.get("cmdline", ""), ev.data.get("exe", ""))
                self._judge(action, target, pid=ev.data.get("pid"))
        for ev in self.net.poll():
            if ev.kind == "outbound_conn":
                action, target = connection_to_action(ev.data.get("rip") or "", ev.data.get("rport") or 0)
                self._judge(action, target, pid=ev.data.get("pid"))

    def run(self, interval=2.0, duration=None):
        start = time.time()
        while duration is None or time.time() - start < duration:
            self.tick()
            time.sleep(interval)
