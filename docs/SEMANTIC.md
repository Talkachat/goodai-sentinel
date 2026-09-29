# Semantic Command Detection

**The gap (REVIEW_3, open since 0.2.x):** literal regex patterns match the *shape* of a
command. Attackers hide intent by splitting tokens — `r"m"`, `s"h"adow` — or via shell
variable indirection — `${x:-rm}`. The characters aren't adjacent, so regex misses them even
though a shell would execute them as `rm` and `shadow`.

**The fix:** `sentinel/semantic.py` de-obfuscates a command the way a shell effectively would,
*then* runs the existing forbidden patterns against the normalized text. The guardrail now
checks both the raw and the de-obfuscated form.

## What it undoes
- **Quote-splitting:** `r"m" -rf /` → `rm -rf /`, `s"h"adow` → `shadow`, `curl x|s"h"` → `curl x|sh`
- **Variable indirection:** `${x:-rm}` → `rm`, `${VAR:=cmd}` → `cmd` (nested-safe)
- **Command substitution:** reveals `$(...)` / backtick contents
- **Backslash splits:** `s\h` → `sh`
- **Line continuations, NBSP, whitespace runs**

## Safety: no new over-blocking
It only *removes* obfuscation, never adds meaning. A real quoted string (which contains a
space or is preceded by a space/operator) is preserved, so benign commands are untouched:
`echo "hello world"`, `git commit -m "removed old file"`, and even `grep "rm this line" notes`
are NOT flagged (`tests/test_semantic.py::test_no_new_overblocking_on_benign`).

## Result
The 10 residual evasions the adaptive red team had been tracking since REVIEW_3 are now closed:
`python -m redteam.adaptive` reports **0 breaches**. This was the project's oldest open
detection gap.

## Limit
This defeats the documented obfuscation families. A determined attacker can invent new
encodings (e.g. base64-decode-then-exec chains); those are caught by the *behavioral* rules
(download-and-exec, temp-exec) rather than by normalization. Semantic detection is one layer,
not a complete intent model — the adaptive loop keeps hunting for the next family.
