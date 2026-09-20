# Defensive-Use Notice

**GoodAI Sentinel is a defensive security tool.** This repository intentionally
contains strings and patterns that resemble malicious commands — for example
`rm -rf`, `vssadmin delete shadows`, reverse-shell syntax, PowerShell encoded
commands, and a red-team attack corpus in `redteam/`.

These exist for exactly one reason: **so the tool can recognise and stop them.**
A malware scanner must contain the signatures of malware; a guardrail must know
what a dangerous action looks like in order to deny it. None of this code
performs an attack. The red-team harness (`redteam/`) fires simulated hostile
actions at the guardrail to prove the guardrail blocks them, and fails CI if any
get through.

If an automated scanner (antivirus, GitHub secret/malware scanning) flags this
repository, that is a false positive triggered by the detection signatures, not
by offensive code.

Do not use any part of this project to attack systems you do not own or lack
explicit permission to test. It is licensed for defensive and research use.
