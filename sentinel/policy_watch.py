"""Zero-downtime policy hot-reload.

A background thread watches the policy file's mtime+size and calls Guardrail.reload()
when it changes. reload() already recompiles rules under a lock and swaps them in place,
so in-flight decide() calls either see the whole old policy or the whole new one — never
a half-applied mix. Pure stdlib (portable, no watchdog dependency); debounced so a
half-written file during an editor save isn't loaded mid-write.
"""
from __future__ import annotations
import threading, time
from pathlib import Path

class PolicyWatcher:
    def __init__(self, guardrail, interval: float = 1.0, debounce: float = 0.3,
                 on_reload=None, on_error=None):
        self.guardrail = guardrail
        self.path = Path(guardrail._policy_path)
        self.interval = interval
        self.debounce = debounce
        self.on_reload = on_reload or (lambda p: None)
        self.on_error = on_error or (lambda e: None)
        self._sig = self._stat()
        self._stop = threading.Event()
        self._t: threading.Thread | None = None
        self.reloads = 0
        self.errors = 0

    def _stat(self):
        try:
            st = self.path.stat()
            return (st.st_mtime_ns, st.st_size)
        except OSError:
            return None

    def poll_once(self) -> bool:
        """Check once; reload if the file changed and is stable. Returns True if reloaded.
        Exposed for tests so the watcher logic can be exercised without the thread."""
        sig = self._stat()
        if sig is None or sig == self._sig:
            return False
        # debounce: wait, then require the signature to hold steady (write finished)
        time.sleep(self.debounce)
        stable = self._stat()
        if stable != sig:
            self._sig = stable          # still changing; pick it up next tick
            return False
        try:
            self.guardrail.reload()
            self._sig = sig
            self.reloads += 1
            self.on_reload(self.path)
            return True
        except Exception as e:           # a broken YAML must NOT crash the watcher or wipe policy
            self.errors += 1
            self.on_error(e)
            self._sig = sig              # don't re-attempt the same broken content every tick
            return False

    def _loop(self):
        while not self._stop.wait(self.interval):
            self.poll_once()

    def force_reload(self) -> bool:
        """Reload unconditionally (ignores mtime). Useful right after wiring up."""
        try:
            self.guardrail.reload(); self._sig = self._stat(); self.reloads += 1
            self.on_reload(self.path); return True
        except Exception as e:
            self.errors += 1; self.on_error(e); return False

    def start(self):
        if self._t and self._t.is_alive():
            return self
        self._stop.clear()
        self._t = threading.Thread(target=self._loop, daemon=True, name="sentinel-policy-watch")
        self._t.start()
        return self

    def stop(self, timeout: float = 2.0):
        self._stop.set()
        if self._t:
            self._t.join(timeout)
