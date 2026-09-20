# Review #3 — GoodAI Sentinel 0.2.1 → 0.2.2

An external review found authorization-boundary bypasses that passing unit tests did not cover. Every finding was reproduced before fixing; each now has a regression test, and the two exploitable-by-string ones (traversal, empty target) are also in the red-team corpus so they can never regress silently.

## Findings and fixes

| # | Sev | Finding (reproduced) | Fix |
|---|---|---|---|
| H1 | High | `write:file /workspace/../../etc/passwd` → allow; empty target bypasses allow-list | `_canon()` resolves `.`/`..` textually before scope checks; filesystem actions with no target are denied |
| H2 | High | Wildcard grant for `/workspace/*` validated `/workspace/.env` (policy-denied) | `Grant.validate()` re-runs the full guardrail on the concrete target; wildcard can't reach a denied file |
| H3 | High | Existing grants survived the kill switch; editing YAML didn't reload | `engage_kill_switch()` + shared revocation generation checked by every grant; `Guardrail.reload()` |
| H4 | High | Any string in `grant.token` still validated | `validate()` authenticates the HMAC over the token's claims before anything else |
| H5 | High | Negative / NaN / inf cost bypassed budget | Non-finite and negative costs are denied; budget charged only on allow |
| H6 | High | 8 concurrent audit writers corrupted the hash chain (`verify()` False) | Chain computation + append serialized under one lock |
| H7 | High | DistAI returned upload content and changed node status despite denial | `check_result` raises on non-allow; coordinator status changes only on allow |
| H8 | High | Built wheel lacked the policy file → `FileNotFoundError` | Policy bundled as package data; `_default_policy_path()` falls back to it; smoke test added |
| M1 | Med | Endpoint check compared hostname while config stored netloc+port | `_host()` normalizes URL / netloc / host:port on both sides |
| M2 | Med | `max_tokens=-1` accepted | Positive-int validation; temperature/top_p range-checked |
| — | Med | Release said 0.2.1 but pyproject built 0.2.0; `cryptography` undeclared | version 0.2.2 everywhere; `cryptography>=42` added to dependencies |

## Still open (documented, not silently shipped)
- Model-integrity findings log but don't yet hard-stop a running job; enforceable quarantine is next.
- Manifest lifecycle: refresh + expiry recheck during operation (currently startup-only).
- Async audit: exception/disk-failure handling and a drained-on-close signal.
- Mobile: allowed-traffic forwarding is still a TODO; not device-tested.
- The token secret still lives in-process; a true authenticated capability needs the policy decision service (the token now at least detects forgery locally).
- `sentinel/default_policy.yaml` is a build-time copy of `policy/agent_guardrails.yaml`; a release step must keep them in sync (or generate one from the other).

## Verify
```
pytest -q            # 62 passed
python -m redteam.run   # 949 dangerous stopped, 0 breaches (now incl. traversal + empty target)
```
