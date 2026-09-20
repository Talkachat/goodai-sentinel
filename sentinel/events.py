from __future__ import annotations
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
import json, os, time

SEVERITY = ("info", "low", "medium", "high", "critical")

@dataclass
class Event:
    """A normalized observation from any sensor."""
    source: str                     # process | network | file | agent | external
    kind: str                       # e.g. new_process, outbound_conn, file_modified, agent_action
    data: dict = field(default_factory=dict)
    ts: float = field(default_factory=time.time)
    id: str = field(default_factory=lambda: os.urandom(6).hex())

    def to_json(self) -> str:
        return json.dumps(asdict(self), default=str)

@dataclass
class Finding:
    """Detector output: something worth attention."""
    event: Event
    rule: str
    severity: str
    reason: str
    score: float = 0.0              # 0..1 anomaly / confidence
    recommended: str = "log"        # log | alert | throttle | isolate | terminate | block

    def __post_init__(self):
        assert self.severity in SEVERITY, self.severity

    def to_json(self) -> str:
        d = asdict(self); d["event"] = asdict(self.event)
        return json.dumps(d, default=str)
