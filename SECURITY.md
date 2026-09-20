# Security Policy

GoodAI Sentinel is a **defensive** security project. We take the safety of this
tool and its users seriously.

## Reporting a vulnerability
Please do **not** open a public issue for security vulnerabilities. Instead, use
GitHub's private vulnerability reporting (Security tab → "Report a vulnerability")
or email the maintainers. We aim to acknowledge within 72 hours.

## Scope
In scope: guardrail bypasses, audit-integrity flaws, privilege or path-scope
escapes, policy-evasion techniques, and issues in the DistAI integration.

Out of scope: findings that require an already-root/compromised host, and the
documented open items in `docs/REVIEW_4.md` (semantic-evasion residuals, mobile
TCP forwarding, per-process token secret).

## A note on the attack signatures in this repository
This project contains attack patterns and a red-team corpus **for detection and
testing only** (see `NOTICE_DEFENSIVE_USE.md`). They are the signatures the tool
defends against, not tools for offense.
