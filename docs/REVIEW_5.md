# Review #5 — response (2026-09-29)

Two external source-reviews of the published repo. Both were performed on a pre-0.3.1
snapshot and could not clone/run the code, so several items they raise as open were in fact
already addressed in 0.3.1. This file records the honest status of every point.

## Already delivered in 0.3.1 (before this review, not yet visible to the reviewer)
| Review item (P0/P1) | Status |
|---|---|
| Central Policy Decision Service | ✅ `pdp/` — /decide /grant /kill /reload /health; same guardrail engine; fleet-wide kill switch |
| Unified token revocation across services | ✅ PDP issues/revokes centrally over HTTP |
| Secret/PII leakage into logs | ✅ `sentinel/masking.py` — redaction before persistence, chain-safe |
| Encoded path-traversal, async-after-close, DistAI runtime re-verify, SQLite parameterization | ✅ fixed in 0.2.4 (REVIEW_4) |

## Raised by this review and addressed now (0.3.2)
| Item | Action |
|---|---|
| **Token race conditions** (checks partly before the lock; validate vs revoke/revoke_all) | Added `tests/test_token_races.py`: proves 0 post-revoke successes (100 trials × 16 threads), use-counter never over-spent (500 threads on count=100 → exactly 100), and `revoke_all` stops concurrent use. **No leak found — the code was already correct; now it is proven and guarded against regression.** |

## Valid and still open (architectural — documented, not silently claimed done)
| Item | Why it's hard / plan |
|---|---|
| **Enforcement depends on the agent calling `request()`** | The deepest point. A malicious agent that never calls `request()` is unseen by the guardrail. True fix = an independent enforcement layer (OS/network interceptor: eBPF/ETW/EndpointSecurity, or a proxy), not a library the agent opts into. This is the next major architecture effort. |
| **10 semantic evasions** (`r"m"`, `${x:-rm}`) | Regex cannot catch a token reconstructed at runtime. Needs a semantic/ML detector. Tracked by the adaptive red-team loop. |
| **Audit tamper-evidence ≠ tamper-proof** | Local hash chain detects edits but not wholesale deletion/replacement. Plan: signed checkpoints → remote append-only storage → independent verification. |
| **Device testing** | Host sensors ran on real macOS (see DEVICE_TESTING.md findings D1–D6); Windows/Linux/Android/iOS still pending real hardware. |
| **dry_run=True default** | Intentional (safe first run). Documented; a clearer startup warning is a small follow-up. |
| **Duplicate packaged policy** | `sentinel/default_policy.yaml` is a build-time copy; needs a sync step in release. |

## Honest bottom line
The reviewers' central thesis is correct and unchanged: the project must move from *a library
that makes security decisions* to *a system that enforces them independently of the (possibly
untrusted) agent*. The PDP is the first half of that (central decision); the missing half is an
enforcement layer the agent cannot bypass. That is the stated next priority.

## Verify
```
pytest -q            # 97 passed (94 + 3 race tests)
python -m redteam.run   # 0 breaches
```
