"""Threat-intel feeds. Ship IOCs from public reports; nodes can also receive signed updates."""
from __future__ import annotations
import json
from pathlib import Path

_DIR = Path(__file__).resolve().parent

class Intel:
    def __init__(self):
        self.domains: set[str] = set(); self.ips: set[str] = set()
        self.file_names: set[str] = set(); self.sha256: set[str] = set(); self.sources: list[str] = []
        for f in sorted(_DIR.glob("*.json")):
            self.load(json.loads(f.read_text()))

    def load(self, doc: dict):
        self.domains |= {d.lower() for d in doc.get("domains", [])}
        self.ips |= set(doc.get("ips", []))
        self.file_names |= {n.lower() for n in doc.get("file_names", [])}
        self.sha256 |= {h.lower() for h in doc.get("sha256", [])}
        if doc.get("source"): self.sources.append(doc["source"])

    def domain_hit(self, host: str) -> str | None:
        h = (host or "").lower().rstrip(".")
        parts = h.split(".")
        for i in range(len(parts) - 1):
            cand = ".".join(parts[i:])
            if cand in self.domains:
                return cand
        return None

INTEL = Intel()
