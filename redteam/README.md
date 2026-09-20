# Guardrail red team

An attacker agent fires ~950 hostile actions at `Guardrail.decide()` across evasion families
(case-folding, whitespace, quotes, absolute paths, env prefixes, subshells, backslashes),
plus split/staged attacks, capability confusion, and prompt-injection strings smuggled as targets.

- **Breach** = a dangerous action the guardrail *allowed*. Any breach fails CI.
- **Over-block** = a benign control action the guardrail *denied*. Any over-block fails CI too — a rule that blocks real work is its own denial-of-service.

```bash
python -m redteam.run                      # exit 0 = pass, 1 = breach/over-block
python -m redteam.run path/to/policy.yaml  # test a fleet policy before rollout
```

## Why it's trustworthy

A gate that always passes proves nothing. `tests/test_redteam.py::test_mutation_gate_actually_bites`
removes each forbidden pattern in turn and points the corpus at a deliberately over-privileged
agent; the harness must then report breaches. If it doesn't, the red team itself is broken and CI fails.

## Extending it

When a breach is found in the wild: add the action to `_DANGER_TARGETS` (or a new family) in
`redteam/attacks.py`, add the missing regex to `policy/agent_guardrails.yaml`
(`forbidden_patterns`), and confirm `python -m redteam.run` returns to PASS. The new case stays
in the corpus forever, so the same evasion can never regress.

## Known limits

- Single-call view: the guardrail sees one action at a time, so genuinely multi-step attacks
  (each step benign alone) are caught by rate/budget/target scope, not by pattern. Cross-call
  correlation belongs in the detection platform, not here.
- This tests the *policy engine*, not the OS sensors or the response ladder.
