# Data Masking & Privacy

The monitor observes command lines, file paths, and agent targets — which can contain
secrets (API keys, tokens, passwords, private keys) and PII (emails, card numbers).
Writing those verbatim to the audit log would itself be a leak. `sentinel/masking.py`
scrubs every record **before** it is persisted.

## What is redacted
- **Secrets:** GitHub tokens (`ghp_…`, `github_pat_…`), AWS keys (`AKIA…`), OpenAI-style
  keys (`sk-…`), Slack tokens (`xox…`), JWTs, and `key=value` / `--flag value` secrets where
  the key name looks like password/secret/token/api_key/auth/bearer/credential.
- **Private key blocks:** `-----BEGIN … PRIVATE KEY----- … -----END … PRIVATE KEY-----`.
- **PII:** email addresses (→ `«email»`) and 13–19 digit card-like runs (last 4 kept).
- **Sensitive keys:** any dict key matching the secret-name pattern has its whole value replaced.

## Design guarantees
- **Central & unbypassable:** redaction runs inside `AuditLog.write` and `AsyncAuditLog.write`,
  so every code path that logs is scrubbed — including the SQLite spill store.
- **Chain-safe:** scrubbing happens before hashing, so the tamper-evident chain still verifies
  (`tests/test_masking.py::test_audit_log_scrubs_and_chain_still_valid`).
- **Forensics preserved:** the shape of the event is kept (you still see it was a `curl` with a
  bearer token to some host), only the secret value is replaced with a placeholder.
- **Low false-positive:** benign paths/commands are untouched
  (`test_benign_content_untouched`).

## Limits
Regex-based masking can miss novel secret formats. It is a defence-in-depth layer, not a
guarantee; treat the audit log as sensitive and restrict access regardless. Add new patterns
in `_PATTERNS` / `_SENSITIVE_KEYS` as needed.
