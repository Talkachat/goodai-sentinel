# GoodAI Sentinel — Architecture Blueprint

**Goal:** an open, embeddable defensive AI module that protects computers, networks, hardware and software from unauthorised or destructive behaviour — whether the actor is a human, malware, or another AI agent, model, or robot.

**Non-goal:** a single all-knowing model. Defence that works is *layered*, *explainable*, and *fails safe*. The AI's job is to see across layers, reason about intent, and act within strict limits.

---

## 1. Design principles

| Principle | Meaning in practice |
|---|---|
| **Deny by default** | An agent can only do what its policy explicitly grants. Unknown = refused. |
| **Reversible first** | Response ladder: log → alert → throttle → freeze (SIGSTOP) → terminate → block. Freeze before kill; preserves forensics. |
| **Human in the loop** | Irreversible or high-impact actions need approval. Autonomy is opt-in, per severity. |
| **Explainable** | Every detection cites a rule or a novelty score; every decision cites the policy clause. No black-box verdicts. |
| **Tamper-evident** | Hash-chained audit log; the policy file and Sentinel's own code are in every agent's deny list. |
| **Never learn from attacks** | The behavioural baseline only learns from events it did *not* flag, so it can't be trained into accepting an intrusion. |
| **Kill switch** | One boolean freezes all agent actions system-wide. |
| **Defence can't be disabled by the thing it defends against** | `forbidden_patterns.disable_defense` and `self_modify` are checked before capabilities — no agent, however privileged, can turn Sentinel off through Sentinel. |

## 2. System layers

```
┌──────────────────────────────────────────────────────────────────┐
│  L6  Governance      policy YAML · approvals UI · kill switch    │
├──────────────────────────────────────────────────────────────────┤
│  L5  Reasoning       LLM triage (optional) · playbooks · scoring │
├──────────────────────────────────────────────────────────────────┤
│  L4  Detection       rules · behavioural baseline · ML models    │
├──────────────────────────────────────────────────────────────────┤
│  L3  Guardrail       capability scope · targets · rate · budget  │
│                      · forbidden patterns · approval gates       │
├──────────────────────────────────────────────────────────────────┤
│  L2  Sensors         process · network · file integrity · agent  │
│                      actions · (ext: syslog, eBPF, cloud audit)  │
├──────────────────────────────────────────────────────────────────┤
│  L1  Enforcement     SIGSTOP/kill · iptables · nice · sandbox    │
│                      · network namespaces · container pause      │
├──────────────────────────────────────────────────────────────────┤
│  L0  Audit           hash-chained JSONL · export to SIEM         │
└──────────────────────────────────────────────────────────────────┘
```

### Data flow

```
 sensors ──Event──▶ Detector ──Finding──▶ Responder ──▶ Enforcement
                                                │
 AI agent ──request()──▶ Guardrail ──Decision───┤
                                                ▼
                                            Audit log
```

Two entry points:

1. **Passive monitoring** (`Sentinel.tick()` / `run()`): sensors observe the host, the detector scores events, the responder acts within its ladder.
2. **Ask-before-act** (`Sentinel.request(agent_id, action, target)`): any AI agent submits an intended action *before* performing it and gets `allow`, `deny`, or `require_approval`. This is the "AI module all can use" — a universal permission check for autonomous systems.

## 3. Component reference

### Sensors (`sentinel/sensors.py`)
- `ProcessSensor` — diffs the process table; emits `new_process` / `process_exited` with cmdline, exe, user, parent.
- `NetworkSensor` — new sockets; `outbound_conn` / `listening_port`.
- `FileIntegritySensor` — SHA-256 of watched trees; `file_created/modified/deleted`.
- `AgentActionSensor` — queue for AI-agent intents.
- **Extension points:** wrap any log source (syslog, journald, cloud audit logs, eBPF, robot telemetry, PLC/SCADA traffic) in a class with a `poll() -> Iterator[Event]` method.

### Detector (`sentinel/detector.py`)
- **Rules** (high precision): download-and-execute, reverse shells, disk wipe, `rm -rf /`, exec from `/tmp`, privilege escalation, sensitive-file changes, C2 ports, ransomware-style mass file change, dangerous agent actions.
- **Baseline** (recall for unknowns): per-feature frequency model — novelty = 1 − p(seen). Learns during warm-up and from unflagged events only. Explainable, zero training data. Swap in an isolation forest / autoencoder / sequence model via the same `score()` interface once you have data.

### Guardrail (`sentinel/guardrail.py` + `policy/agent_guardrails.yaml`)
Evaluation order (first match wins):
1. Kill switch
2. Forbidden patterns (disable defence, self-modify, destroy data, exfiltrate, reverse shell, privesc, credential access, unbounded self-replication, firmware writes, log destruction)
3. Capability scope (`read:*`, `write:file`, `deploy:*` …)
4. Target scope (`allow_targets` / `deny_targets` globs)
5. Rate limit per agent
6. Budget per agent (cost/tokens/any unit)
7. Approval gates for irreversible actions
8. Allow

Agents are matched by glob on `agent_id` (`coder-*`, `ops-*`, `untrusted-*`), inheriting `defaults`.

### Responder (`sentinel/responder.py`)
- Severity caps the automatic response: `medium/high → alert`, `critical → isolate`. Anything above the cap is queued for human approval unless `autonomous=True`.
- `dry_run=True` by default: nothing touches the machine until you pass `--live`.
- `AuditLog`: append-only, each record hashes the previous — `verify()` detects any edit.

## 4. Deployment topologies

| Scale | Setup |
|---|---|
| Single machine | `python -m sentinel --watch /etc /home/me --live` as a systemd service |
| Fleet | One Sentinel per host, ship audit JSONL to a central collector (SIEM/OpenSearch); central policy repo with signed YAML |
| AI-agent platform | Embed `Sentinel.request()` as middleware in the agent framework's tool-call path (LangChain/LangGraph/AutoGen/MCP gateway). Every tool call = one `request()`. |
| Robots / IoT | Sensor adapters for motor commands, geofences, and firmware writes; guardrail rules for physical envelopes (speed, force, zones); enforcement = e-stop relay |

## 5. Threat model coverage

| Threat | Layer that catches it |
|---|---|
| Malware download & exec, reverse shell | Rules (process), C2 port (network) |
| Ransomware | Mass file change + sensitive file rules |
| Insider / stolen credentials | Baseline novelty (new user, new parent, new dst) |
| Rogue AI agent: exfiltrating secrets | Guardrail `exfiltrate`, `credential_access`, deny_targets |
| Rogue AI agent: disabling defences / self-modifying | Guardrail `disable_defense`, `self_modify` (checked first, unbypassable) |
| Rogue AI agent: runaway loops / self-replication | Rate limit, budget, `spawn_unbounded` |
| Firmware / hardware bricking | `control_hardware`, `destroy_data` |
| Log tampering | Hash-chained audit + `disable_logging` pattern |
| Prompt injection driving an agent | Injection can't grant capabilities the policy doesn't — actions still pass through the guardrail |

## 6. Hardening checklist before production
- Run Sentinel as a dedicated low-privilege user with only the capabilities enforcement needs (`CAP_KILL`, `CAP_NET_ADMIN`).
- Make `policy/` and `sentinel/` read-only (immutable attribute, signed releases).
- Ship the audit log off-host in near-real-time.
- Add an approvals channel (Slack/PagerDuty/email) as the `approver` callback.
- Replace regex rules with a maintained detection library (Sigma rules) and the baseline with a trained model once you have ≥2 weeks of benign data.
- Red-team it: see `RESEARCH_PLAN.md` §4.

## 7. Latency tiers for `request()` on hot paths

| Tier | When | Mechanism | Cost |
|---|---|---|---|
| 1 Grant once | High-frequency loops (matching, batch writes, control loops) | `grant()` → signed capability token; `validate()` in-process | ≤ 1.5 µs |
| 2 Fast sync | Per-op check unavoidable, op is 1 ms+ | `request()` with `async_audit=True`; decision in memory, audit via background writer | ~40 µs |
| 3 Shadow | Op cannot tolerate 40 µs **and is reversible** | Decision runs alongside the op; deny → revoke grants + roll back | 0 on path |
| 4 Windowed | Streams / sensor feeds | Evaluate 100 ms windows; enforce by not renewing tokens | amortised |

Rules: irreversible actions never use tier 3; a guardrail timeout fails *closed* for irreversible actions and *open-with-shadow* for reversible ones. Novelty shapes the grant (count × (1 − novelty), TTL likewise), so the hot loop never evaluates novelty itself.
