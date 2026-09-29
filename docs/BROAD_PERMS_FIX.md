# Broad-Permission Coverage Fix (from the 100k stress finding)

## What the 100k test revealed
A user-run stress test (100,000 attack-derived inputs) showed: with the restricted policy, all
were denied. But against a **deliberately over-privileged agent**, ~27% were allowed. Correct
diagnosis: some denials were relying on the agent's limited *scope*, not on the detection engine
recognizing the dangerous *pattern*. A truly malicious agent with broad grants would slip past.

## Root cause
Several dangerous OS commands were recognized by the host-level rules (`sentinel/platform.py`)
but were **missing from the central `forbidden_patterns`** in the policy — so the agent guardrail
didn't catch them when scope was wide. Also, patterns using backslashes failed because the
guardrail normalizes `\` → `/` before matching.

## Fix
Added 8 pattern families to `forbidden_patterns`, slash-normalization-aware and tolerant of
whitespace/case/hyphen-split obfuscation:
`win_firewall_off, backup_destroy, sam_dump, ps_encoded, firmware_flash, clear_event_log,
lolbin_exec, defender_off`.

## Result (dangerous seeds allowed under FULL permissions)
| | before | after |
|---|---|---|
| allowed | 253 / 949 | **1 / 949** |

The single remaining case is a genuine multi-stage attack (`chmod +x /tmp/a && /tmp/a`) where
each stage is individually benign; it is caught by rate/budget correlation, not by a single
pattern, and is a documented known limit. **No new over-blocking** — benign commands like
`git reset --hard`, `echo set the value`, `npm run build` remain allowed
(`tests/test_broad_perms.py`).

## Why this matters
It moves these denials from "blocked because the agent lacked permission" to "blocked because the
action is recognized as dangerous" — enforcement that holds even for a fully-privileged, malicious
agent. Exactly the gap the reviews called out as P0.
