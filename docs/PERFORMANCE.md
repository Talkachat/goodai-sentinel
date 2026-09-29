# Performance & Stress

Measured with `python -m bench.stress` on one core (Python 3.12, no GPU). Numbers are
illustrative of the shape, not a guarantee for every machine.

| Benchmark | Result |
|---|---|
| Single-thread guardrail | ~32,000 decisions/sec · p50 29µs · p95 47µs · p99 62µs · **0 wrong verdicts** |
| Concurrent (8 threads, 160k decisions) | ~32,000 decisions/sec · **0 wrong verdicts · 0 errors** |
| Async audit under load (50k writes, with masking) | ~38,000 writes/sec · **0 dropped · chain valid · secrets redacted** |

## What the stress test proves
- **Correctness under concurrency:** 160,000 decisions across 8 threads produced zero wrong
  verdicts and zero exceptions — the guardrail's locking holds under contention.
- **No audit loss under load:** 50,000 rapid writes, none dropped; overflow spills rather than
  drops, the hash chain still verifies, and PII/secret masking still fires.
- **Bounded latency:** p99 stays under ~65µs; the rare millisecond-scale max is GC, not a stall.
- **Concurrency doesn't degrade throughput:** 8 threads ≈ single-thread rate (the hot path is
  short and the critical section small).

## Note on rate limits under load
When an agent's own `rate_limit`/`budget` is exhausted, the guardrail correctly starts denying
— that is the system working, not an error. The benchmark uses unbounded test agents to isolate
raw decision performance; the correctness tests exercise the bounded behavior separately.

## Regression guard
`tests/test_stress.py` runs a smaller version in CI: it fails the build if correctness under
load breaks, throughput collapses, or the audit starts dropping data.

## Limits
This measures the in-process decision path. The PDP (network service) adds HTTP overhead
(~tens of µs to low ms depending on transport); use capability tokens (`grant`) for hot loops
to avoid a network call per operation, as documented in the PDP README.
