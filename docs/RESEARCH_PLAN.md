# Research Plan — Defensive AI ("the good AI")

A 12-month plan to grow Sentinel from a rule+baseline prototype into a robust, open, general-purpose defensive AI. Each phase has a measurable exit criterion.

---

## 0. Questions this program must answer

1. **Detection:** Can an AI reliably distinguish malicious from merely unusual behaviour across processes, networks, files, *and* AI-agent actions — with a false-positive rate operators will tolerate (< 1 alert / host / day)?
2. **Control:** Can we constrain autonomous agents (LLM agents, robots) so that no capability, prompt injection, or self-modification lets them exceed policy — and prove it?
3. **Response:** How much autonomy can the defender safely have? Where does human approval remain mandatory?
4. **Robustness:** Does the defender survive adversaries who know its design, including adversarial AI attackers?
5. **Trust:** Can every decision be explained to a human well enough to audit and appeal?

## 1. Phase A — Foundations (months 1–2)

- **Telemetry corpus.** Collect ≥ 2 weeks of benign host telemetry from ≥ 20 diverse machines (dev laptops, CI runners, servers). Label with system role.
- **Attack corpus.** Reproduce MITRE ATT&CK techniques in a lab (Atomic Red Team, Caldera). Record the same telemetry.
- **Agent-action corpus.** Instrument 3 open-source agent frameworks (LangGraph, AutoGen, an MCP gateway) to log every tool call. Seed with prompt-injection attacks (AgentDojo, InjecAgent benchmarks).
- **Baseline metrics.** Run current Sentinel on all corpora; record precision/recall per rule, novelty-score ROC.
- *Exit:* reproducible eval harness with per-technique detection rates.

## 2. Phase B — Detection models (months 3–5)

| Track | Approach | Success metric |
|---|---|---|
| Process/file | Sequence models over (parent→child, cmdline tokens, file-op bursts) — isolation forest → small transformer | ≥ 90 % ATT&CK technique recall at ≤ 1 FP/host/day |
| Network | Flow-level features + destination reputation; graph anomaly on host↔host edges | Detect C2 beaconing with ≥ 85 % recall |
| Agent actions | Classifier on (agent role, action, target, recent context) predicting *intent class*; LLM triage for the ambiguous middle band | ≥ 95 % block rate on injection benchmarks, ≤ 2 % false blocks on benign tasks |
| Fusion | Cross-source correlation (a new process *and* a new outbound *and* a sensitive file read within 30 s) | Reduce alert volume ≥ 50 % via correlation |

Constraint carried from the prototype: **models only train on unflagged data** (poisoning resistance). Evaluate this explicitly (Phase D).

## 3. Phase C — Guardrail formalisation (months 4–6)

- Express `agent_guardrails.yaml` in a formal policy language (Cedar or OPA/Rego) and **prove** the invariants: (a) forbidden patterns are unbypassable, (b) no policy grants write access to the policy or Sentinel itself, (c) rate/budget caps are monotone.
- Capability-based tokens: agents receive short-lived scoped tokens rather than identities; a stolen token can't exceed its scope.
- Physical-world extension: geofence, speed, force and duty-cycle envelopes for robots; e-stop as the enforcement primitive.
- Multi-agent: detect collusion/coordination (agents splitting a forbidden action into allowed fragments) via cross-agent sequence analysis.
- *Exit:* published formal spec + model-checked proofs of invariants (a)–(c).

## 4. Phase D — Adversarial robustness (months 6–9)

Red-team the defender with attackers who have the source code:

1. **Evasion:** obfuscated commands, living-off-the-land binaries, slow-and-low ransomware under the mass-change threshold.
2. **Poisoning:** attempt to teach the baseline that attack behaviour is normal; measure drift.
3. **Defence disabling:** every route to stopping Sentinel (signals, resource exhaustion, log flooding, policy corruption).
4. **AI-vs-AI:** an attacker LLM agent tasked with achieving objectives past the guardrail; log every success and turn it into a rule/test.
5. **Injection through data:** sensor data containing text designed to manipulate the LLM triage layer.

*Exit:* each finding closed with a test in `tests/`; regression suite runs in CI.

## 5. Phase E — Autonomy & response (months 8–10)

- Simulation environment (containers + emulated network) to measure *harm from acting* vs *harm from waiting* for each response type.
- Learn approval policies from operator decisions (which alerts humans approve instantly → candidates for autonomy).
- Response playbooks: isolate → snapshot → notify → rollback, with automatic revert if confidence drops.
- *Exit:* autonomy matrix (severity × confidence × reversibility → action) validated by operators.

## 6. Phase F — Explainability & governance (months 9–12)

- Every finding renders a one-paragraph human explanation + the evidence chain.
- Appeals: agents/operators can contest a decision; contested decisions feed back into rule review.
- Transparency: publish detection rules, policy schema, eval results, and red-team findings.
- Governance: who may change policy, signed policy releases, change review.
- *Exit:* external audit of the system against the threat model in `ARCHITECTURE.md` §5.

## 7. Open research problems (no solved answer yet)

- **Intent inference** for agents when the action is benign but the goal is not (e.g. reading many public files to reconstruct a secret).
- **Bounded autonomy proofs** for learned components — can a neural policy be shown never to exceed a symbolic guardrail?
- **Cross-organisation defence**: sharing threat signals between Sentinels without leaking private telemetry (federated learning, secure aggregation).
- **Self-defence of the defender**: a defender that reasons about attacks on itself without becoming the most privileged — and therefore most dangerous — component.

## 8. Ethics & safety constraints on this research

- Defence only. No offensive tooling is built or released; attack reproduction uses existing public frameworks in isolated labs.
- Telemetry collection requires informed consent and is minimised (no file contents, no keystrokes).
- The defender must never gain capabilities beyond what enforcement requires — the guardrail applies to Sentinel itself.
- Findings that would enable attacks are disclosed responsibly to affected projects before publication.
