# Adaptive red-team loop (enhancement #4)

`redteam/adaptive.py` turns the static corpus into a discovery tool. It mutates known-dangerous
commands (whitespace, tabs, quote-splitting, shell-variable indirection, case-mixing, NBSP
smuggling, path prefixes) and searches for variants that the guardrail's forbidden patterns do
NOT deny, using a deliberately over-privileged agent so only the pattern layer is under test.

```bash
python -m redteam.adaptive          # writes redteam/proposed_rules.json
```

The report contains:
- `breaches` — dangerous variants that were allowed.
- `proposed_forbidden_patterns` — candidate regexes generalized from the breaches, whitespace/
  quote/case tolerant.
- `residual_breaches_needing_semantic_detection` — breaches no regex can catch because the
  malicious token is reconstructed at runtime (`r"m"`, `${x:-rm}`). These are the honest limit
  of pattern-matching and belong to a future semantic/ML detector.

## Safety invariant

Proposals are **never** auto-merged into the live policy (`test_proposals_never_auto_merged`).
An auto-generated regex is a suggestion for a human to review, add to
`policy/agent_guardrails.yaml`, and back with a regression case in `redteam/attacks.py`. Auto-
merging would create a false sense of safety and risk over-blocking real work.

## What it already found

On 0.2.2 the loop found 42 evasions of the shipping patterns (e.g. `rm  -rf` with double
spaces, `Rm -rf` case-mix, `sc  stop  WinDefend`). 0.2.3 added whitespace/quote/case-tolerant
patterns (`ws_destroy`, `ws_disable_defense`, `ws_ransomware`) that close 32 of them; the
remaining 10 are quote-split / variable-indirection and are tracked for semantic detection.
