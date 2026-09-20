# Installing Sentinel as a service

| OS | Command |
|---|---|
| Linux (systemd) | `sudo cp -r . /opt/goodai && sudo cp deploy/sentinel.service /etc/systemd/system/ && sudo systemctl enable --now sentinel` |
| macOS (launchd) | `sudo cp -r . /opt/goodai && sudo cp deploy/com.goodai.sentinel.plist /Library/LaunchDaemons/ && sudo launchctl load -w /Library/LaunchDaemons/com.goodai.sentinel.plist` |
| Windows (Task Scheduler) | Open PowerShell **as Administrator** in the project folder: `.\deploy\install-service.ps1` |

Requirements everywhere: Python 3.10+, `pip install psutil pyyaml`.

## What needs admin, and what works without it

| Capability | No admin | Admin / root |
|---|---|---|
| Process monitoring, dangerous-command rules | ✔ (own processes; other users' cmdlines may be hidden) | ✔ all processes |
| File-integrity on your own files | ✔ | ✔ + system dirs |
| Network connection listing | Linux ✔ · Windows ✔ · macOS ✖ (needs root) | ✔ |
| AI-agent guardrail (`request()` / `grant()`) | ✔ full | ✔ |
| Freeze / terminate a process | own processes only | any |
| Block an IP (iptables / pf / netsh) | ✖ | ✔ |

## Per-OS notes
- **macOS:** Full Disk Access may be needed for file-integrity on `~/Library`. IP blocking uses a pf table named `sentinel`; see the comment in the plist.
- **Windows:** Rules cover PowerShell encoded/hidden execution, LOLBins (certutil, mshta, regsvr32, rundll32, bitsadmin), shadow-copy deletion, Run-key persistence, Defender/firewall tampering, and event-log clearing. Command-line inspection needs the task to run as SYSTEM (the script does this).
- **Linux:** `nft` is used when present and `iptables` is not; otherwise `iptables`.
- **Android / iOS:** no host-level monitoring is possible for third-party apps. Use the guardrail (`request()` / `grant()`) inside your app or on the server side; the host layer is desktop/server only.
