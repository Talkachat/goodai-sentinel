# Review #2 — GoodAI Sentinel 0.1 → 0.2

Independent code review performed after the external review, with every claim reproduced before being accepted. All ten findings are fixed in 0.2.0 and each has a regression test in `tests/test_review_fixes.py`.

## Findings

| # | Severity | Finding | Reproduced | Fix |
|---|---|---|---|---|
| F1 | High | `rule_mass_file_change({})` was built once at import, so every `Detector` shared one ransomware window. A second detector fired after seeing one file. | Yes | `default_rules()` factory; each `Detector` gets fresh state. |
| F2 | **High (new)** | Every `grant()` was silently halved after warm-up: the baseline had no agent history, and unseen feature kinds scored 0.5 novelty. All hot-path grants ran at half the requested count. | Yes: 3 grants of 1000 → 500 each | `Baseline.score()` ignores feature kinds with no history; allowed agent actions now feed the baseline, so a *new* agent is novel while a known one is not. |
| F3 | Medium (new) | `unexpected_listener` fired on every port when `pid` is unknown, which is every port on macOS without root. | Yes | Unknown-pid listeners flag only known-bad ports. |
| F4 | Medium | `AgentActionSensor` swap in `poll()` raced with `submit()`; events could be lost. | Yes | Lock around both. Test: 8,000 events, 4 producers, 0 lost. |
| F5 | High | File-integrity sensor re-read and re-hashed every file every cycle, followed symlinks, and had no size cap. | Yes | Stat cache (size, mtime, inode, ctime), symlinks skipped, `max_files` cap with `truncated` flag, forced full rehash every N polls to defeat timestamp forgery. |
| F6 | High | Async audit dropped records on queue overflow. | Yes | Never drops: 250 ms back-pressure, then synchronous write to a hash-chained `.spill` sidecar with a `spilled` counter. |
| F7 | Medium (new) | Expired grants were never removed (51 kept after 50 expired); `validate()` did not normalise targets. | Yes | Sweep every 100 grants or 1 s; targets normalised. |
| F8 | Medium (new) | `Guardrail.decide()` mutated rate/budget state without a lock; budget was charged for actions that returned `require_approval` and never ran. | Yes | Lock; budget charged only on `allow`. |
| F9 | Low (new) | `Responder.pending` grew without bound. | Yes | Capped at 1,000; evictions are audited. |
| F10 | Low | Plain `pytest` failed (no package config). | Yes | `pyproject.toml` with `pythonpath`, console script, version 0.2.0. |

## Rejected or deferred from the external review

- "Critical" for network-sensor recall: real, but a recall gap, not a safety flaw; the guardrail is unaffected. Deferred to native sensors (eBPF/ETW/EndpointSecurity).
- Off-host audit anchoring, signed policies, shared rate/budget state, distributed tokens: agreed, but these are architecture work (policy decision service), not patches. See `ARCHITECTURE.md` and the scale-up ordering.
- Product positioning: strategy, not code.

## Still open (known, documented)

- Windows and macOS paths are simulation-tested; Swift port uncompiled.
- Hash-chained audit detects tampering by non-root only; root can recompute the chain. Off-host anchoring required.
- The HMAC token secret is per process; tokens cannot be verified across services until the policy decision service exists.
- Regex rules are the first layer, not the last.

## Verification

```
pytest -q            # 47 passed (37 existing + 10 regression)
python demo.py       # audit chain valid: True
python -m mobile.export_policy   # conformance 15/15 against the Python engine
```
