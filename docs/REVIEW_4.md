# Review #4 — independent cowork audit of 0.2.3

A fresh adversarial pass after the three prior reviews, focused on areas they hadn't probed:
alternate traversal encodings, injection into the new SQLite store, lifecycle edge cases
(close-after-write, policy-file deletion), and whether the "still open" items from earlier
reviews were actually closed. Every claim below was reproduced before fixing.

## New findings (fixed in 0.2.4)

| # | Sev | Finding (reproduced) | Fix |
|---|---|---|---|
| N1 | High | Percent-encoded traversal (`/workspace/%2e%2e/%2e%2e/etc/passwd`) returned **allow**. Harmless at the OS layer, but a downstream consumer that URL-decodes the target could escape scope. | Targets containing `%2e`, `%2f`, `%5c`, `%00` are denied (`encoded_target`). Defense in depth: the guardrail never decodes, it refuses. |
| N2 | Med | `AsyncAuditLog.write()` after `close()` was silently accepted, risking lost/unchained audit data. | `write()` after close raises `RuntimeError`; `close()` now returns whether the queue fully drained and records `drained_on_close`. |
| N3 | Med | DistAI model integrity was verified only at startup; a model tampered on disk *between jobs* produced a finding but the job still ran (the "logs but doesn't stop" gap from review #2). | `_integrity_tick()` re-verifies the loaded model against the signed manifest on any change in the models dir and raises `ShieldError` (`model_tamper_runtime`) before the job proceeds — enforceable quarantine. |

## Checked and found already-correct (no change)

- SQLite spill store is injection-safe (parameterized queries); a `severity` of `high'; DROP TABLE audit; --` inserts one row and `verify()` still passes.
- Backslash traversal (`..\\..\\`), case traversal (`/WORKSPACE/../../`), and `./../../` are all denied by the canonicalizer.
- `....//` is **not** a bypass: it resolves to a literal `..../` directory on real filesystems (confirmed against `os.path.normpath`), so treating it as a normal segment is correct.
- Null-byte and newline targets are denied (fail allow-list).
- Multiline (`echo hi\nrm -rf /`) and fullwidth-unicode (`ｒｍ`) dangerous commands are denied.
- Wildcard grants still cannot reach traversal targets (`validate` re-checks the concrete path).
- Policy-file deletion at runtime doesn't crash the watcher or wipe the running policy.
- Adaptive red team still finds only the 10 known semantic residuals (quote-split, var-indirection) — no regression from hardening.

## Still open (unchanged, documented)

- The 10 semantic-residual evasions (`r"m"`, `${x:-rm}`) need a non-regex detector; tracked by the adaptive loop.
- Mobile TCP forwarding is delegated to a pluggable stack (fail-closed); UDP is implemented on both platforms; none is device-tested.
- Token secret is still per-process (forgery detected locally); cross-service capabilities need the policy decision service.
- `sentinel/default_policy.yaml` is a build-time copy; a release step must keep it synced.

## Verify
```
pytest -q            # 88 passed
python -m redteam.run   # 0 breaches / 0 over-blocks
```

## Assessment
Level is solid for a prototype: four independent review rounds, each finding fewer and shallower issues (12 → 10 → then boundary bugs → now 3 mostly defense-in-depth). No breach-class bypass remains in the guardrail. The honest blockers to "production" are unchanged and architectural, not defects: the policy decision service (shared state, cross-service tokens, off-host audit anchoring), a semantic detector, and real device/OS testing of the sensors and mobile tunnels.
