"""Async hash-chained audit: callers enqueue (non-blocking); a background thread
batches, chains, and flushes. Same verify() semantics as AuditLog."""
from __future__ import annotations
import hashlib, json, queue, threading, time
from pathlib import Path
from .responder import AuditLog
from .audit_store import AuditStore
from .masking import redact


class AsyncAuditLog(AuditLog):
    def __init__(self, path, flush_ms: float = 50.0, max_queue: int = 100_000,
                 spill_strategy: str = "spill_all", sample_rate: float = 0.1,
                 backpressure_s: float = 0.25):
        super().__init__(path)
        self.q: queue.Queue = queue.Queue(maxsize=max_queue)
        self.flush_s = flush_ms / 1000
        self.backpressure_s = backpressure_s
        self.dropped = 0                            # always 0; kept for compatibility
        self.spilled = 0
        self._spill = AuditStore(str(self.path) + ".spill.db",
                                 strategy=spill_strategy, sample_rate=sample_rate)
        self._stop = threading.Event()
        self._t = threading.Thread(target=self._loop, daemon=True); self._t.start()

    def write(self, record: dict):                 # hot path: enqueue only
        if self._stop.is_set():
            raise RuntimeError("AsyncAuditLog is closed; refusing write (audit integrity)")
        rec = {**redact(record), "ts": time.time()}  # scrub secrets/PII before que/spill
        try:
            self.q.put_nowait(rec)
            return
        except queue.Full:
            pass
        try:                                       # back-pressure for up to 250 ms
            self.q.put(rec, timeout=self.backpressure_s)
            return
        except queue.Full:
            pass
        # Still full: audit data is never dropped. Write synchronously to a spill file
        # (own hash chain) and count it so operators can see the writer is falling behind.
        self.spilled += 1
        self._spill.write(rec)                      # queryable SQLite; high-severity never dropped

    def _loop(self):
        while not self._stop.is_set() or not self.q.empty():
            batch = []
            deadline = time.time() + self.flush_s
            while time.time() < deadline:
                try:
                    batch.append(self.q.get(timeout=self.flush_s))
                except queue.Empty:
                    break
            if batch:
                self._flush(batch)

    def _flush(self, batch):
        lines = []
        for rec in batch:
            rec["prev"] = self._prev
            h = hashlib.sha256(json.dumps(rec, sort_keys=True, default=str).encode()).hexdigest()
            rec["hash"] = h; self._prev = h
            lines.append(json.dumps(rec, default=str))
        with self.path.open("a") as f:
            f.write("\n".join(lines) + "\n")

    def spill_query(self, **kw):
        return self._spill.query(**kw)

    def spill_high_severity_kept(self) -> int:
        return self._spill.count("high") + self._spill.count("critical")

    def close(self, timeout: float = 5.0) -> bool:
        """Signal stop, drain, and report whether the queue fully flushed within timeout."""
        self._stop.set(); self._t.join(timeout)
        drained = self.q.empty()
        self._spill.close()
        self.drained_on_close = drained
        return drained
