"""Queryable spill store for audit overflow (enhancement #2).

When the async writer's in-memory queue saturates, records must not be lost. This store
provides a configurable strategy for what to do under saturation:

  - "spill_all"       : every overflow record goes to SQLite (default; zero drop).
  - "sample_low"      : high-severity records always spill; low-severity are sampled at
                        `sample_rate` so a flood of noise can't unbound the store, while
                        security-critical telemetry is still never dropped.

Severity is read from the record's finding.severity (or a top-level "severity"), defaulting
to "medium". "high"/"critical" are always kept. The store is indexed by (ts, severity) so it
can be queried under load, and it keeps its own hash chain so spilled data is tamper-evident.
"""
from __future__ import annotations
import hashlib, json, random, sqlite3, threading, time

_ALWAYS_KEEP = {"high", "critical"}

def _severity(rec: dict) -> str:
    f = rec.get("finding")
    if isinstance(f, dict) and f.get("severity"):
        return str(f["severity"])
    return str(rec.get("severity", "medium"))


class AuditStore:
    def __init__(self, path: str, strategy: str = "spill_all", sample_rate: float = 0.1):
        assert strategy in ("spill_all", "sample_low"), strategy
        self.path = path
        self.strategy = strategy
        self.sample_rate = sample_rate
        self._lock = threading.Lock()
        self._prev = "0" * 64
        self.kept = 0
        self.sampled_out = 0                 # low-severity records intentionally not stored
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("""CREATE TABLE IF NOT EXISTS audit(
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, severity TEXT,
            prev TEXT, hash TEXT, record TEXT)""")
        self._db.execute("CREATE INDEX IF NOT EXISTS ix_sev ON audit(severity)")
        self._db.execute("CREATE INDEX IF NOT EXISTS ix_ts ON audit(ts)")
        self._db.commit()
        row = self._db.execute("SELECT hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
        if row:
            self._prev = row[0]

    def write(self, record: dict) -> bool:
        """Store a record. Returns True if kept, False if intentionally sampled out.
        High/critical severity is ALWAYS kept regardless of strategy."""
        sev = _severity(record)
        if self.strategy == "sample_low" and sev not in _ALWAYS_KEEP:
            if random.random() > self.sample_rate:
                with self._lock:
                    self.sampled_out += 1
                return False
        rec = {**record, "ts": record.get("ts", time.time())}
        blob = json.dumps(rec, sort_keys=True, default=str)
        with self._lock:
            h = hashlib.sha256((self._prev + blob).encode()).hexdigest()
            self._db.execute("INSERT INTO audit(ts,severity,prev,hash,record) VALUES(?,?,?,?,?)",
                             (rec["ts"], sev, self._prev, h, blob))
            self._db.commit()
            self._prev = h
            self.kept += 1
        return True

    # ---- query API (the point of using SQLite over a flat file) ----
    def query(self, severity: str | None = None, since: float | None = None, limit: int = 1000):
        sql = "SELECT ts,severity,record FROM audit"
        cond, args = [], []
        if severity: cond.append("severity=?"); args.append(severity)
        if since is not None: cond.append("ts>=?"); args.append(since)
        if cond: sql += " WHERE " + " AND ".join(cond)
        sql += " ORDER BY id DESC LIMIT ?"; args.append(limit)
        out = []
        for t, sev, r in self._db.execute(sql, args):
            rec = json.loads(r); rec["ts"] = t; rec["severity"] = sev
            out.append(rec)
        return out

    def count(self, severity: str | None = None) -> int:
        if severity:
            return self._db.execute("SELECT COUNT(*) FROM audit WHERE severity=?", (severity,)).fetchone()[0]
        return self._db.execute("SELECT COUNT(*) FROM audit").fetchone()[0]

    def verify(self) -> bool:
        prev = "0" * 64
        for _id, prevh, h, blob in self._db.execute("SELECT id,prev,hash,record FROM audit ORDER BY id"):
            if prevh != prev or hashlib.sha256((prev + blob).encode()).hexdigest() != h:
                return False
            prev = h
        return True

    def close(self):
        with self._lock:
            self._db.close()
