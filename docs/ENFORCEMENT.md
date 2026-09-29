# Independent Enforcement Layer

**The gap (review #5, P0):** the guardrail only sees an action if the agent *calls* `request()`.
A malicious agent that skips it is invisible. This layer observes actions from **outside** the
agent — at the OS level — and applies the **same policy**, so a forbidden action is caught even
when no one asked permission.

## How it works
```
OS event (new process / outbound conn)
        │  observed by ProcessSensor / NetworkSensor (read-only, not the agent)
        ▼
   mapper → (agent_id="os-activity", action, target)
        ▼
   the SAME Guardrail.decide()          ← single source of truth
        ▼
   deny → audit + (live mode) freeze the process     ← independent of the agent
```

The guardrail remains the one place policy lives; the enforcer just asks on the OS's behalf.
Undeclared `rm -rf /`, `curl|sh`, and SSH-key exfil are caught with no agent cooperation
(`tests/test_enforcement.py`), and in live mode a real offending process is suspended
(reversible-first, preserving forensics).

## Run
```bash
python -m enforcement --duration 60      # observe + audit only
python -m enforcement --live             # also freeze denied processes (needs privileges)
```

## Honest limits (what this is and isn't)
- This is **detective + reactive** enforcement: it observes then acts. It is *not* kernel-level
  *prevention* — a very fast process could complete before the poll sees it.
- True prevention needs kernel hooks: **eBPF LSM / seccomp-bpf on Linux, EndpointSecurity on
  macOS, WFP/minifilter on Windows**. That is the next step and is intentionally not faked here.
- Polling cadence (`--interval`) trades latency for CPU; short-lived processes may be missed.
- Attribution: OS activity is judged as the `os-activity` policy identity, tunable in
  `policy/agent_guardrails.yaml`.

This layer meaningfully narrows the "agent didn't ask" gap; closing it fully is a kernel-module
effort tracked in the roadmap.
