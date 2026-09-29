"""Responder: graded, reversible-first actions. Destructive actions need a human
unless `autonomous=True` AND severity is critical. Everything is logged.

Real-world hooks (iptables, kill, network namespace) are behind `dry_run`.
Default dry_run=True so nothing happens to your machine until you opt in.
"""
from __future__ import annotations
import json, subprocess, threading, time
from pathlib import Path
from typing import Callable
from .events import Finding
from .masking import redact
from . import platform as plat

try:
    import psutil
except ImportError:
    psutil = None

LADDER = ["log", "alert", "throttle", "isolate", "terminate", "block"]
ESCALATE_AT = {"info": "log", "low": "log", "medium": "alert", "high": "alert", "critical": "isolate"}


class AuditLog:
    """Append-only JSONL. Hash-chained so tampering is detectable."""
    def __init__(self, path: str | Path):
        self.path = Path(path); self.path.parent.mkdir(parents=True, exist_ok=True)
        self._prev = "0" * 64
        self._lock = threading.Lock()
        if self.path.exists():
            lines = self.path.read_text().strip().splitlines()
            if lines:
                self._prev = json.loads(lines[-1]).get("hash", self._prev)

    def write(self, record: dict):
        import hashlib
        record = redact(record)                # scrub secrets/PII before anything is persisted
        with self._lock:                       # chain computation + append are one critical section
            record = {**record, "ts": time.time(), "prev": self._prev}
            h = hashlib.sha256(json.dumps(record, sort_keys=True, default=str).encode()).hexdigest()
            record["hash"] = h; self._prev = h
            with self.path.open("a") as f:
                f.write(json.dumps(record, default=str) + "\n")

    def verify(self) -> bool:
        import hashlib
        prev = "0" * 64
        for line in self.path.read_text().splitlines():
            rec = json.loads(line); h = rec.pop("hash")
            if rec["prev"] != prev or hashlib.sha256(
                    json.dumps(rec, sort_keys=True, default=str).encode()).hexdigest() != h:
                return False
            prev = h
        return True


class Responder:
    def __init__(self, audit: AuditLog, dry_run: bool = True, autonomous: bool = False,
                 approver: Callable[[Finding, str], bool] | None = None,
                 notify: Callable[[str], None] | None = None):
        self.audit, self.dry_run, self.autonomous = audit, dry_run, autonomous
        self.approver = approver or (lambda f, a: False)     # default: nobody approves
        self.notify = notify or (lambda msg: print(msg))
        self.pending: list[tuple[Finding, str]] = []
        self.max_pending = 1000                  # oldest are evicted (and audited) beyond this

    def handle(self, f: Finding) -> str:
        action = f.recommended
        # never exceed what severity justifies without a human
        cap = ESCALATE_AT.get(f.severity, "log")
        if LADDER.index(action) > LADDER.index(cap) and not self.autonomous:
            if self.approver(f, action):
                outcome = self._execute(f, action)
            else:
                self.pending.append((f, action))
                if len(self.pending) > self.max_pending:
                    old_f, old_a = self.pending.pop(0)
                    self.audit.write({"evicted_pending": old_f.rule, "action": old_a})
                outcome = f"pending_approval:{action}"
                self._execute(f, "alert")
        else:
            outcome = self._execute(f, action)
        self.audit.write({"finding": json.loads(f.to_json()), "action": action, "outcome": outcome,
                          "dry_run": self.dry_run})
        return outcome

    # ---- actions ----
    def _execute(self, f: Finding, action: str) -> str:
        fn = getattr(self, f"_do_{action}", self._do_log)
        return fn(f)

    def _do_log(self, f): return "logged"

    def _do_alert(self, f):
        self.notify(f"[{f.severity.upper()}] {f.rule}: {f.reason}")
        return "alerted"

    def _do_throttle(self, f):
        pid = f.event.data.get("pid")
        if pid and psutil and not self.dry_run:
            try: plat.throttle(psutil.Process(pid))
            except Exception as e: return f"throttle_failed:{e}"
        return f"throttled pid={pid} (dry_run={self.dry_run})"

    def _do_isolate(self, f):
        pid = f.event.data.get("pid")
        if pid and psutil and not self.dry_run:
            try: psutil.Process(pid).suspend()      # freeze, don't kill: preserves forensics (all OSes)
            except Exception as e: return f"isolate_failed:{e}"
        return f"isolated(suspend) pid={pid} (dry_run={self.dry_run})"

    def _do_terminate(self, f):
        pid = f.event.data.get("pid")
        if pid and psutil and not self.dry_run:
            try: psutil.Process(pid).terminate()
            except Exception as e: return f"terminate_failed:{e}"
        return f"terminated pid={pid} (dry_run={self.dry_run})"

    def _do_block(self, f):
        ip = f.event.data.get("rip")
        if ip and not self.dry_run:
            cmd = plat.block_ip_cmd(ip)
            try: subprocess.run(cmd, check=True, capture_output=True)
            except Exception as e: return f"block_failed:{e}"
        return f"blocked ip={ip} (dry_run={self.dry_run})"
