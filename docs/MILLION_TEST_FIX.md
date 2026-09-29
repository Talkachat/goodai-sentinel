# Million-input test findings & fixes (v0.4.6)

A user-run 1,000,000-input stress test (attack-derived, no real execution) on v0.4.5:
- **Normal policy:** 1,000,000 / 1,000,000 denied in 68s. ✓
- **Broad-permission agent:** 4,212 allowed, in three families. Each was triaged:

| Family | Count | Verdict after triage | Action |
|---|---|---|---|
| Traversal | 2,106 | **Not a breach** — real traversal (`/workspace/../../etc/passwd`) is denied; these were benign paths that resolve *inside* the allowed root. | none needed (correct) |
| Split execution | 1,053 | **Real gap** — chained commands running from /tmp (`chmod +x /tmp/a && /tmp/a`, `curl … > /tmp/x; sh /tmp/x`) slipped the patterns. | added `chained_exec` + `temp_exec_chain` patterns |
| Empty target | 1,053 | **Mostly a test artifact** — a real empty target (`""`) is denied; appending a unique id made it non-empty. But whitespace-only targets should count as empty. | guardrail now treats whitespace-only target as empty |

## Result after fixes
Dangerous seeds allowed under FULL permissions: **0 / 949** (was 253 before this session).
No new over-blocking: `git add . && git commit`, `ls; pwd`, `cd x && npm build` all still allowed.

## Honest note
"0 / 949" means the current corpus is fully covered — it does **not** mean the system is
unbreakable. It means the known attack families, including their obfuscations, are caught. New
attack *techniques* (not just new obfuscations of old ones) remain the frontier; the adaptive
red team keeps hunting for them. The one structurally hard case — genuine multi-stage attacks
where each step is benign in isolation — is handled by rate/budget correlation and the
independent enforcer, not by single-command patterns.
