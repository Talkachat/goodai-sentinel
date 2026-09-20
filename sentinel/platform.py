"""OS abstraction: everything that differs between Linux, macOS and Windows lives here.
Detector/responder import from this module instead of hard-coding Linux paths/commands."""
from __future__ import annotations
import os, re, subprocess, sys
from pathlib import Path

OS = ("windows" if sys.platform.startswith("win")
      else "macos" if sys.platform == "darwin"
      else "linux")
IS_WIN = OS == "windows"


def norm_path(p: str) -> str:
    """Normalise for glob matching: forward slashes; case-folded on Windows."""
    p = (p or "").replace("\\", "/")
    return p.lower() if IS_WIN else p


HOME = norm_path(str(Path.home()))

# ---------------- default watch paths (file-integrity) ----------------
DEFAULT_WATCH = {
    "linux":   ["/etc"],
    "macos":   ["/etc", "/Library/LaunchDaemons", "/Library/LaunchAgents", f"{Path.home()}/Library/LaunchAgents"],
    "windows": [r"C:\Windows\System32\drivers\etc",
                f"{Path.home()}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
                r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"],
}[OS]

# ---------------- temp/exec-from-temp dirs ----------------
TEMP_DIRS = {
    "linux":   ("/tmp/", "/dev/shm/", "/var/tmp/"),
    "macos":   ("/tmp/", "/private/tmp/", "/var/folders/", f"{Path.home()}/Downloads/"),
    "windows": ("c:/windows/temp/", "/appdata/local/temp/", "/downloads/", "c:/users/public/"),
}[OS]

# ---------------- sensitive paths (substring match after norm_path) ----------------
SENSITIVE_PATHS = {
    "linux":   ("/etc/passwd", "/etc/shadow", "/etc/sudoers", "/root/.ssh", "/.ssh/", "/etc/cron",
                "/boot/", "authorized_keys", "id_rsa", "/etc/ld.so.preload"),
    "macos":   ("/etc/passwd", "/etc/sudoers", "/.ssh/", "authorized_keys", "id_rsa",
                "/Library/LaunchDaemons", "/Library/LaunchAgents", "/etc/pam.d", "/Library/Keychains",
                "/Library/Application Support/com.apple.TCC", "/etc/hosts"),
    "windows": ("/windows/system32/config/", "/windows/system32/drivers/etc/hosts", "/.ssh/",
                "authorized_keys", "id_rsa", "/start menu/programs/startup/", "/windows/system32/tasks/",
                "/ntds.dit", "/sam", "/windows/system32/drivers/", "/appdata/roaming/microsoft/credentials"),
}[OS]

# ---------------- dangerous command patterns ----------------
_COMMON = (
    r"(curl|wget)[^|]*\|\s*(ba|z)?sh"          # download-and-execute
    r"|base64\s+(-d|--decode)"
    r"|nc\s+.*-e\s|/dev/tcp/|mkfifo\s"
    r"|rm\s+-rf\s+/(\s|$)|rm\s+-rf\s+~"
    r"|mkfs\.|dd\s+if=.*of=/dev/(sd|hd|disk|nvme)"
    r"|shred\s"
)
_MAC = (
    r"|osascript\s+-e\s+.*(do shell script|with administrator privileges)"
    r"|launchctl\s+(load|bootstrap)\s+.*(/tmp|/var/folders|Downloads)"
    r"|csrutil\s+disable|spctl\s+--master-disable"
    r"|tccutil\s+reset|security\s+(dump-keychain|find-generic-password)"
    r"|diskutil\s+(eraseDisk|secureErase|zeroDisk)"
    r"|xattr\s+-d\s+com\.apple\.quarantine"
)
_WIN = (
    r"|powershell[^|]*(-e(nc|ncodedcommand)?\s|-nop\s|-w(indowstyle)?\s+hidden|iex\s|invoke-expression|downloadstring|frombase64string|bypass)"
    r"|certutil[^|]*(-urlcache|-decode)"
    r"|mshta\s+(http|vbscript|javascript)|regsvr32[^|]*/i:http|rundll32[^|]*javascript"
    r"|bitsadmin[^|]*/transfer|wmic[^|]*process\s+call\s+create"
    r"|vssadmin[^|]*delete\s+shadows|wbadmin\s+delete|bcdedit[^|]*(recoveryenabled\s+no|bootstatuspolicy)"
    r"|cipher\s+/w|format\s+[a-z]:\s*/|diskpart"
    r"|reg\s+(add|delete)[^|]*(\\run|\\image file execution options|\\winlogon|\\services)"
    r"|schtasks\s+/create[^|]*(\\temp\\|\\appdata\\|/ru\s+system)"
    r"|net\s+user\s+\S+\s+\S+\s+/add|net\s+localgroup\s+administrators.*\s/add"
    r"|sc\s+(stop|delete|config)\s+(windefend|sentinel|mpssvc|eventlog)"
    r"|set-mppreference[^|]*disable|netsh\s+advfirewall\s+set\s+\w+\s+state\s+off"
    r"|wevtutil\s+cl\s|auditpol[^|]*/clear"
)
SUSPICIOUS_CMD = re.compile(_COMMON + {"linux": "", "macos": _MAC, "windows": _WIN}[OS], re.I)

PRIVESC_CMD = re.compile({
    "linux":   r"\b(sudo\s+su|pkexec|setuid|chmod\s+[ug]\+s)\b",
    "macos":   r"\b(sudo\s+su|chmod\s+[ug]\+s|with administrator privileges|dscl\s+.*-append\s+/Groups/admin)\b",
    "windows": r"(runas\s+/user:.*administrator|fodhelper|eventvwr\.exe|computerdefaults|sdclt|cmstp\s|-verb\s+runas)",
}[OS], re.I)

DEFENSE_SERVICES = {
    "linux":   r"sentinel|auditd|ufw|iptables|nftables|selinux|apparmor|firewalld|falco|clamav",
    "macos":   r"sentinel|pfctl|pf\b|gatekeeper|spctl|csrutil|xprotect|mrt",
    "windows": r"sentinel|windefend|mpssvc|eventlog|sysmon|wscsvc|securityhealth",
}[OS]

# ---------------- enforcement ----------------
def block_ip_cmd(ip: str) -> list[str]:
    """Command that drops outbound traffic to `ip`. Needs admin/root on all OSes."""
    if OS == "windows":
        return ["netsh", "advfirewall", "firewall", "add", "rule", f"name=Sentinel-block-{ip}",
                "dir=out", "action=block", f"remoteip={ip}"]
    if OS == "macos":
        # uses a pf table; create once with: `echo "table <sentinel> persist" >> /etc/pf.conf && pfctl -f /etc/pf.conf`
        return ["pfctl", "-t", "sentinel", "-T", "add", ip]
    if subprocess.run(["which", "nft"], capture_output=True).returncode == 0 and not os.path.exists("/sbin/iptables"):
        return ["nft", "add", "rule", "inet", "filter", "output", "ip", "daddr", ip, "drop"]
    return ["iptables", "-I", "OUTPUT", "-d", ip, "-j", "DROP"]


def throttle(proc) -> None:
    """Lowest priority, portable (psutil.Process)."""
    if OS == "windows":
        import psutil
        proc.nice(psutil.IDLE_PRIORITY_CLASS)
    else:
        proc.nice(19)


def is_admin() -> bool:
    if OS == "windows":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.geteuid() == 0


def service_instructions() -> str:
    return {
        "linux": "systemd: copy deploy/sentinel.service to /etc/systemd/system && systemctl enable --now sentinel",
        "macos": "launchd: copy deploy/com.goodai.sentinel.plist to /Library/LaunchDaemons && sudo launchctl load -w it",
        "windows": "Run as Administrator: deploy\\install-service.ps1  (uses Task Scheduler, no extra tools)",
    }[OS]
