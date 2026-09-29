# Changelog

## 0.3.1 — 2026-09-28
- Added: audit **PII/secret masking** (`sentinel/masking.py`). Tokens, API keys, private-key
  blocks, key=value secrets, emails and card numbers are redacted before any record is written
  (sync + async + spill). Redaction is central, unbypassable, and chain-safe.
- Added: `docs/PRIVACY.md`.
- Tests: masking suite (7) added.

## 0.2.4 — 2026-09-13
Independent cowork audit (review #4); see docs/REVIEW_4.md.
- Fixed (N1): percent-encoded / null-byte traversal in targets is denied (encoded_target).
- Fixed (N2): audit write-after-close raises; close() reports drain status.
- Fixed (N3): DistAI re-verifies the model against the manifest on runtime change and stops the
  job (enforceable quarantine) instead of only logging.
- Verified safe (no change): SQLite injection, backslash/case/dot traversal, ....// literal,
  null/newline/multiline/unicode commands, wildcard-grant traversal, watcher on file deletion.
- Tests: 88 total.

## 0.2.3 — 2026-09-13 (in progress)
- Added (#3): policy hot-reload watcher (`sentinel/policy_watch.py`); `--watch-policy` CLI flag.
  Debounced, survives broken YAML without wiping policy, propagates kill switch to live grants.
- Added (#2): queryable SQLite spill store (`sentinel/audit_store.py`) with backpressure
  strategies (spill_all / sample_low). High/critical audit records are never dropped; low
  severity can be sampled under saturation. Chain-verified and query-indexed by severity+ts.
- Added (#4): adaptive red-team loop (`redteam/adaptive.py`) — mutates attacks to find guardrail
  evasions and proposes candidate rules (never auto-merged). Found 42 evasions; policy hardened
  with whitespace/quote/case-tolerant patterns closing 32. Non-blocking CI step uploads proposals.
- Hardened: added ws_destroy / ws_disable_defense / ws_ransomware forbidden patterns.
- Added: UDP/DNS forwarding for BOTH Android (DatagramChannel + protect) and iOS (NWConnection +
  NEPacketTunnelFlow), at parity, with idle-flow reapers. TCP delegated to a pluggable stack on
  both, dropped-closed when absent. Cross-platform packet-math parity proven byte-for-byte
  (reference == Kotlin == Swift) and pinned in tests/test_mobile_parity.py.
- Tests: 81 total (Python); Kotlin packet-math compiler-verified offline.

## 0.2.2 — 2026-09-13
Authorization-boundary hardening after review #3 (see docs/REVIEW_3.md).
- Fixed: path traversal and empty-target bypass of allow-lists (H1).
- Fixed: wildcard grants could reach policy-denied targets (H2).
- Fixed: kill switch + policy reload now propagate to live grants (H3).
- Fixed: capability tokens are authenticated; forged tokens rejected (H4).
- Fixed: negative/NaN/inf costs rejected (H5).
- Fixed: concurrent audit writes no longer corrupt the hash chain (H6).
- Fixed: DistAI honours upload/status denials (H7).
- Fixed: policy bundled in the wheel; installed smoke test (H8).
- Fixed: endpoint host+port normalisation (M1); positive max_tokens + param ranges (M2).
- Packaging: version 0.2.2, cryptography dependency declared.
- Tests: 62 total; red team now covers traversal and empty target.

## 0.2.1 — 2026-09-12
- Added: adversarial red-team harness (`redteam/`) and CI gate (`.github/workflows/security.yml`).
  ~950 hostile actions across evasion families; fails the build on any breach or over-block.
- Added: mutation test proving the gate detects removed forbidden patterns (50 tests total).

## 0.2.0 — 2026-09-12
Hardening release after two reviews (see `docs/REVIEW_2.md`).
- Fixed: shared ransomware-window state across Detector instances (F1).
- Fixed: capability grants silently halved after warm-up (F2).
- Fixed: listener rule noise when pid unknown (F3).
- Fixed: lost agent events under concurrency (F4).
- Improved: file-integrity sensor uses a stat cache, skips symlinks, caps file count, and force-rehashes periodically (F5).
- Changed: async audit never drops records; overflow spills to a chained sidecar file (F6).
- Fixed: expired grants swept; target normalisation in `Grant.validate` (F7).
- Fixed: guardrail locking; budget charged only on `allow` (F8).
- Fixed: bounded pending-approval queue (F9).
- Added: `pyproject.toml`, `sentinel` console script, plain `pytest` support (F10).
- Added: 10 regression tests (47 total).

## 0.1.0
Initial prototype: sensors, detector, guardrail, responder, capability tokens, async audit, cross-platform layer, mobile ports, DistAI integration, September 2026 threat-report rules.