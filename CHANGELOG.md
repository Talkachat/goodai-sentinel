# Changelog

## 0.5.1 — 2026-09-30
- Added: **desktop Control Center** (`desktop/`) — one icon (🛡️ GoodAI Sentinel.app) with a
  menu for start / stop / status / open-dashboard / restart / last-events / stop-dashboard,
  plus live status of both the guard and the dashboard. Replaces the separate desktop buttons.
- Added: `desktop/install-control-center.command` (builds the .app) and desktop README.

## 0.5.0 — 2026-09-29
- Added: **81 distinct attack-technique families** (`redteam/attacks_extended.py`) — real MITRE-style
  techniques, not seed mutations. Found 87 genuine gaps the million-mutation tests never could.
- Added: 26 forbidden-pattern families (interpreter exec, PATH/lib hijack, cron/systemd/launchd
  persistence, decode-then-exec, fileless, privesc, cred theft, exfil, IMDS, defense evasion,
  destruction, container secrets, supply chain, firmware, Windows persistence, LSASS, LOLBins).
- Added: ANSI-C hex/octal decoding to the semantic layer; raw-target normalization before
  slash-stripping. Technique coverage: 41/128 -> 124/127 (97.6%), 0 over-blocking.
- Added: `docs/EXTENDED_ATTACKS.md`, `tests/test_extended_attacks.py`. 129 tests total.

## 0.4.6 — 2026-09-29
- Fixed (from 1M-input stress test): split/chained execution from temp dirs
  (chmod +x /tmp/a && /tmp/a, curl > /tmp/x; sh /tmp/x) now denied via new chained_exec /
  temp_exec_chain patterns; whitespace-only targets now count as empty. Dangerous-under-full-
  perms: 253 -> 0 / 949. No new over-blocking (git add . && git commit etc. still allowed).
- Triaged the 3 allowed families: traversal (benign, correct), split (fixed), empty (test artifact + fix).
- Added: `docs/MILLION_TEST_FIX.md`. Hardened mutation gate for overlapping coverage. 126 tests.

## 0.4.5 — 2026-09-29
- Fixed (from 100k stress finding): dangerous OS commands were denied only by scope, not by
  pattern, so a fully-privileged agent could slip them past. Added 8 forbidden-pattern families
  (firewall-off, backup-destroy, SAM-dump, encoded-PowerShell, firmware-flash, log-clear, LOLBins,
  Defender-off), slash- and obfuscation-tolerant. Dangerous seeds allowed under FULL perms:
  253/949 -> 1/949 (remaining = documented multi-stage case). No new over-blocking.
- Added: `docs/BROAD_PERMS_FIX.md`, `tests/test_broad_perms.py`. 126 tests total.

## 0.4.4 — 2026-09-29
- Added: **read-only incident dashboard** (`dashboard/`) — zero-dependency (stdlib only) web view
  of the audit log with severity cards, filters, and a live table. Proven read-only. `docs`/README.
- Added: `docs/VM_TESTING.md` — safe test-VM setup for the upcoming kernel-level (eBPF) phase.
- Tests: 123 total.

## 0.4.3 — 2026-09-29
- Added: **stress / performance benchmark** (`bench/stress.py`) + regression tests. Measured
  ~32k decisions/sec (p99 62µs), 0 wrong verdicts across 160k concurrent decisions, and
  ~38k audit writes/sec with 0 dropped and masking intact under load. `docs/PERFORMANCE.md`.
- Tests: 118 total.

## 0.4.2 — 2026-09-29
- Added: **signed audit anchoring** (`sentinel/audit_anchor.py`). Signed, counted checkpoints
  (HMAC or Ed25519) shipped to a remote append-only sink turn the log from tamper-EVIDENT into
  tamper-PROOF: deletion, truncation, wholesale wipe and forgery are all detected (review P1).
- Added: `AuditLog.enable_checkpoints()`, `RemoteAnchor`, `verify_checkpoints()`, `docs/AUDIT_ANCHORING.md`.
- Tests: 115 total.

## 0.4.1 — 2026-09-29
- Added: **semantic command detection** (`sentinel/semantic.py`). De-obfuscates quote-splitting
  (r"m"), variable indirection (${x:-rm}), backslash splits and command substitution, then runs
  forbidden patterns on the normalized form. Closes the 10 residual evasions open since REVIEW_3
  — adaptive red team now reports 0 breaches. No new over-blocking (real quoted strings preserved).
- Added: `docs/SEMANTIC.md`.
- Tests: 108 total.

## 0.4.0 — 2026-09-29
- Added: **independent enforcement layer** (`enforcement/`) — observes OS activity (processes,
  connections) and applies the SAME guardrail policy WITHOUT the agent calling request(),
  answering the deepest review finding (P0: enforcement must not depend on the agent).
  Catches undeclared rm -rf /, curl|sh, SSH-key exfil; live mode freezes the offending process.
- Added: `docs/ENFORCEMENT.md` (incl. honest limits: detective+reactive, not yet kernel-level).
- Added: os-activity policy identity; `python -m enforcement` CLI.
- Tests: 103 total.

## 0.3.2 — 2026-09-29
- Added: token concurrency tests (`tests/test_token_races.py`) — proves validate() is safe
  against concurrent revoke/revoke_all and the use-counter is never over-spent (review #5 P0).
- Added: `docs/REVIEW_5.md` — honest status of both external reviews.
- Tests: 97 total.

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