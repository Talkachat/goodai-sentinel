"""Detection rules derived from Anthropic's September 2026 threat report.
Each rule cites the case it answers. Wired into Detector.DEFAULT_RULES via detector.py."""
from __future__ import annotations
import hashlib, re, time
from collections import defaultdict
from pathlib import Path
from .events import Event, Finding
from .intel import INTEL
from .platform import norm_path

# GTG-50014 / GTG-50029 / GTG-50020: AI API keys and cloud tokens are the loot.
SECRET_RX = re.compile(
    r"sk-ant-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{32,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{40,}"
    r"|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35}|-----BEGIN [A-Z ]*PRIVATE KEY-----|eyJhbGciOi[A-Za-z0-9_-]{20,}\.")
EXFIL_TOOLS = re.compile(r"\b(curl|wget|nc|ncat|scp|rsync|Invoke-WebRequest|iwr|Invoke-RestMethod|irm)\b", re.I)
# Prompt-injected agents dumping their own environment / cloud metadata (LiteLLM, eval-sandbox cases)
ENV_DUMP = re.compile(r"169\.254\.169\.254|metadata\.google\.internal|/proc/self/environ|\bprintenv\b|\benv\b\s*(\||>)"
                      r"|Get-ChildItem\s+env:|os\.environ|\$ENV:|\.env\b.*(cat|type|curl|base64)", re.I)
# GTG-20006: implants that freeze security updates so new signatures never arrive
DISABLE_UPDATES = re.compile(r"sc\s+(stop|config)\s+wuauserv|net\s+stop\s+wuauserv|Set-Service\s+wuauserv.*Disabled"
                             r"|softwareupdate\s+--schedule\s+off|systemctl\s+(stop|mask|disable)\s+(unattended-upgrades|apt-daily|dnf-automatic|clamav)"
                             r"|reg\s+add.*WindowsUpdate.*NoAutoUpdate|Set-MpPreference.*-DisableRealtimeMonitoring", re.I)
# Fake "Claude Code"/AI harness installers (GTG-50021) — AI-branded binary running from download/temp dirs
AI_BRAND = re.compile(r"claude|anthropic|openai|chatgpt|cursor|copilot|kimi|gemini", re.I)
TEMPISH = ("/tmp/", "/downloads/", "/appdata/local/temp/", "/var/folders/", "c:/users/public/")
# GTG-50029: webshells in font assets, must-use plugins, poisoned uploads
WEBSHELL_PATHS = re.compile(r"wp-content/mu-plugins/|wp-content/uploads/.*\.(php|phtml|phar)$|/(fonts?|assets)/.*\.(php|phtml)$"
                            r"|\.(woff2?|ttf|css|js)\.php$", re.I)
PHP_TAG = re.compile(rb"<\?php|<\?=|eval\s*\(|base64_decode\s*\(", re.I)


def rule_known_ioc(ev: Event):
    """Network destinations, file names and hashes published in the report."""
    if ev.kind == "outbound_conn":
        ip = ev.data.get("rip") or ""
        if ip in INTEL.ips:
            return Finding(ev, "ioc_ip", "critical", f"Outbound to published attacker IP {ip}", 0.97, "block")
        host = ev.data.get("host") or ""
        hit = INTEL.domain_hit(host) if host else None
        if hit:
            return Finding(ev, "ioc_domain", "critical", f"Outbound to published attacker domain {hit}", 0.97, "block")
    if ev.kind == "new_process":
        name = (ev.data.get("name") or "").lower()
        exe = norm_path(ev.data.get("exe") or "").lower()
        if name in INTEL.file_names or exe.rsplit("/", 1)[-1] in INTEL.file_names:
            return Finding(ev, "ioc_filename", "critical", f"Known malware file name {name or exe}", 0.9, "isolate")
        h = ev.data.get("sha256")
        if h and h.lower() in INTEL.sha256:
            return Finding(ev, "ioc_hash", "critical", f"Known malware hash {h[:16]}…", 0.99, "terminate")
    if ev.kind == "agent_action":
        blob = f"{ev.data.get('action','')} {ev.data.get('target','')}"
        for d in INTEL.domains:
            if d in blob.lower():
                return Finding(ev, "ioc_domain", "critical", f"Agent targeting published attacker domain {d}", 0.97, "block")
    return None


def rule_credential_exposure(ev: Event):
    """A credential-shaped string on a command line, especially with a transfer tool: exfil in progress."""
    if ev.kind not in ("new_process", "agent_action"):
        return None
    blob = ev.data.get("cmdline") or f"{ev.data.get('action','')} {ev.data.get('target','')}"
    if SECRET_RX.search(blob or ""):
        if EXFIL_TOOLS.search(blob):
            return Finding(ev, "credential_exfil", "critical", "API key/token on a transfer command line", 0.95, "terminate")
        return Finding(ev, "credential_on_cmdline", "high", "API key/token exposed on a command line", 0.8, "alert")
    return None


def rule_env_dump(ev: Event):
    """Agent/process reading its own secrets or cloud metadata — the LiteLLM / eval-sandbox injection pattern."""
    if ev.kind not in ("new_process", "agent_action"):
        return None
    blob = ev.data.get("cmdline") or f"{ev.data.get('action','')} {ev.data.get('target','')}"
    if ENV_DUMP.search(blob or ""):
        sev = "critical" if ev.kind == "agent_action" else "high"
        return Finding(ev, "env_or_metadata_dump", sev, f"Secret/metadata harvesting: {blob[:100]}", 0.85, "block")
    return None


def rule_disable_updates(ev: Event):
    if ev.kind != "new_process":
        return None
    cmd = ev.data.get("cmdline") or ""
    if DISABLE_UPDATES.search(cmd):
        return Finding(ev, "disable_security_updates", "critical", f"Security updates being disabled: {cmd[:100]}", 0.9, "terminate")
    return None


def rule_fake_ai_installer(ev: Event):
    if ev.kind != "new_process":
        return None
    exe = norm_path(ev.data.get("exe") or "").lower()
    if AI_BRAND.search(exe.rsplit("/", 1)[-1]) and any(t in exe for t in TEMPISH):
        return Finding(ev, "ai_branded_binary_from_temp", "high",
                       f"AI-tool-branded binary running from a download/temp dir: {exe}", 0.8, "isolate")
    return None


def rule_webshell_drop(ev: Event):
    """Server-side: PHP where only assets/uploads/plugins should be, or PHP tags inside a font/css file."""
    if ev.kind not in ("file_created", "file_modified"):
        return None
    path = norm_path(ev.data.get("path", ""))
    if WEBSHELL_PATHS.search(path):
        return Finding(ev, "webshell_drop", "critical", f"Executable web file in asset/upload path: {path}", 0.9, "alert")
    if re.search(r"\.(woff2?|ttf|otf|css|svg|png|jpg)$", path, re.I):
        try:
            head = Path(ev.data["path"]).read_bytes()[:65536]
            if PHP_TAG.search(head):
                return Finding(ev, "webshell_in_asset", "critical", f"PHP code hidden in asset file {path}", 0.95, "alert")
        except (OSError, KeyError):
            pass
    return None


def rule_polymorphic_rebuild(window_s: float = 3600, distinct: int = 3):
    """GTG-20006's evasion loop: the same tool keeps coming back as a *different binary*.
    Same process name, N distinct executable hashes in a window. Per-detector state."""
    seen: dict[str, dict[str, float]] = defaultdict(dict)   # name -> {hash: last_seen}

    def _hash(exe: str) -> str | None:
        try:
            p = Path(exe)
            if p.is_file() and p.stat().st_size < 64_000_000:
                return hashlib.sha256(p.read_bytes()).hexdigest()
        except OSError:
            return None
        return None

    def _rule(ev: Event):
        if ev.kind != "new_process":
            return None
        exe, name = ev.data.get("exe") or "", (ev.data.get("name") or "").lower()
        if not exe or not name:
            return None
        h = ev.data.get("sha256") or _hash(exe)
        if not h:
            return None
        ev.data["sha256"] = h
        now = time.time()
        hs = seen[name]; hs[h] = now
        for k in [k for k, t in hs.items() if now - t > window_s]:
            del hs[k]
        if len(hs) >= distinct:
            return Finding(ev, "polymorphic_rebuild", "high",
                           f"'{name}' seen as {len(hs)} different binaries in {int(window_s/60)} min (auto-evasion loop?)",
                           0.8, "isolate")
        return None
    return _rule


def report_rules():
    return [rule_known_ioc, rule_credential_exposure, rule_env_dump, rule_disable_updates,
            rule_fake_ai_installer, rule_webshell_drop, rule_polymorphic_rebuild()]
