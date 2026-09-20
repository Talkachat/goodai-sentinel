"""Sensors turn host/agent state into Events. All are read-only observers."""
from __future__ import annotations
import hashlib, threading
from pathlib import Path
from typing import Iterable, Iterator
from .events import Event

try:
    import psutil
except ImportError:  # keep module importable without psutil
    psutil = None


class ProcessSensor:
    """Emits new_process / process_exited by diffing the process table."""
    def __init__(self):
        self._seen: dict[int, dict] = {}

    def poll(self) -> Iterator[Event]:
        if psutil is None:
            return
        current: dict[int, dict] = {}
        for p in psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline", "username", "create_time"]):
            try:
                info = dict(p.info)
                info["cmdline"] = " ".join(info.get("cmdline") or [])
                current[info["pid"]] = info
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        if self._seen:  # skip the first snapshot
            for pid, info in current.items():
                if pid not in self._seen:
                    yield Event("process", "new_process", info)
            for pid, info in self._seen.items():
                if pid not in current:
                    yield Event("process", "process_exited", info)
        self._seen = current


class NetworkSensor:
    """Emits outbound_conn / listening_port for new sockets."""
    def __init__(self):
        self._seen: set[tuple] = set()
        self._primed = False

    def poll(self) -> Iterator[Event]:
        if psutil is None:
            return
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            return
        now: set[tuple] = set()
        for c in conns:
            key = (c.pid, c.status, c.laddr.port if c.laddr else None,
                   c.raddr.ip if c.raddr else None, c.raddr.port if c.raddr else None)
            now.add(key)
            if self._primed and key not in self._seen:
                kind = "listening_port" if c.status == "LISTEN" else "outbound_conn"
                yield Event("network", kind, {
                    "pid": c.pid, "status": c.status,
                    "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else None,
                    "raddr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else None,
                    "rip": c.raddr.ip if c.raddr else None,
                    "rport": c.raddr.port if c.raddr else None,
                })
        self._seen, self._primed = now, True


class FileIntegritySensor:
    """Hashes watched paths and emits file_modified / file_created / file_deleted."""
    def __init__(self, paths: Iterable[str], max_bytes: int = 5_000_000, max_files: int = 50_000,
                 full_rehash_every: int = 30):
        self.paths = [Path(p) for p in paths]
        self.max_bytes, self.max_files = max_bytes, max_files
        self.full_rehash_every = full_rehash_every
        self._baseline: dict[str, str] | None = None
        self._stat: dict[str, tuple] = {}        # path -> (size, mtime_ns, ino, ctime_ns)
        self._polls = 0
        self.truncated = False

    def _snapshot(self) -> dict[str, str]:
        """Hash only files whose (size, mtime, inode, ctime) changed, plus a full rehash every N
        polls to defeat timestamp forgery. Symlinks are never followed. Bounded by max_files."""
        self._polls += 1
        full = self.full_rehash_every and self._polls % self.full_rehash_every == 0
        snap, seen, count = {}, {}, 0
        for root in self.paths:
            if root.is_symlink() or not root.exists():
                continue
            files = [root] if root.is_file() else root.rglob("*")
            for f in files:
                if count >= self.max_files:
                    self.truncated = True
                    break
                try:
                    if f.is_symlink() or not f.is_file():
                        continue
                    st = f.stat()
                    if st.st_size > self.max_bytes:
                        continue
                    key = (st.st_size, st.st_mtime_ns, st.st_ino, st.st_ctime_ns)
                    sp = str(f); count += 1
                    if not full and self._stat.get(sp) == key and sp in (self._baseline or {}):
                        snap[sp] = self._baseline[sp]
                    else:
                        snap[sp] = hashlib.sha256(f.read_bytes()).hexdigest()
                    seen[sp] = key
                except (OSError, PermissionError):
                    continue
        self._stat = seen
        return snap

    def poll(self) -> Iterator[Event]:
        snap = self._snapshot()
        if self._baseline is None:
            self._baseline = snap
            return
        for path, h in snap.items():
            old = self._baseline.get(path)
            if old is None:
                yield Event("file", "file_created", {"path": path, "sha256": h})
            elif old != h:
                yield Event("file", "file_modified", {"path": path, "sha256": h, "prev": old})
        for path in self._baseline:
            if path not in snap:
                yield Event("file", "file_deleted", {"path": path})
        self._baseline = snap


class AgentActionSensor:
    """Receives actions proposed by AI agents and turns them into events.
    Other AI systems call `submit()` BEFORE acting; the guardrail decides allow/deny."""
    def __init__(self):
        self._queue: list[Event] = []
        self._lock = threading.Lock()

    def submit(self, agent_id: str, action: str, target: str = "", **extra) -> Event:
        ev = Event("agent", "agent_action", {"agent_id": agent_id, "action": action,
                                             "target": target, **extra})
        with self._lock:
            self._queue.append(ev)
        return ev

    def poll(self) -> Iterator[Event]:
        with self._lock:
            q, self._queue = self._queue, []
        yield from q
