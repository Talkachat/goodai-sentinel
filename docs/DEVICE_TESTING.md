
## Findings from the first real-device run (macOS, Intel, 2026-09-28)

Recorded during the first hardware test — these are real observations, not hypotheticals.

| # | Observation | Status |
|---|---|---|
| D1 | Runs correctly on macOS Intel with Python 3.13; 81/83 tests pass (2 skipped: they need `cryptography`, which needs a Rust/OpenSSL toolchain to build on Intel macOS). | ✅ works |
| D2 | File-integrity sensor detects changes on a real machine: creating/editing/deleting files in a watched dir produced `events: 11–12`. | ✅ works |
| D3 | Runs as a persistent `launchd` LaunchAgent (`RunAtLoad`+`KeepAlive`); survives and auto-starts. | ✅ works |
| D4 | **Audit file is not created until a *finding* occurs.** A user reasonably expects an audit file to exist (with at least a startup record) once the service runs. On a quiet machine `audit.jsonl` never appears, which looks like a failure even though monitoring works. | 🟠 improve |
| D5 | Status line ("Sentinel up on macos…") is written to stderr, so under launchd it lands in `err.log`, which looks alarming though it is normal. | 🟠 improve |
| D6 | Without root, the process sensor sees limited process info on macOS; only file events were exercised. Full coverage needs elevated privileges. | ⚠️ documented |

### Suggested fixes (small, safe)
- On startup, write one `service_started` record to the audit log so the file always exists and operators can confirm the service is live.
- Add a periodic `heartbeat` record (e.g. every N minutes) so a quiet machine still shows the service is alive and the audit chain is advancing.
- Send the startup status line to stdout (info), keep stderr for real errors, so `err.log` stays clean.
