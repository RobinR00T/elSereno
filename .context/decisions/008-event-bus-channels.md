---
id: 008
title: Typed channel event bus with split persistence paths
status: accepted
date: 2026-04-19
phase: F0
---

# ADR-008: Typed channel event bus with split persistence paths

## Context
Findings are produced in bursts; audit entries must form a strict hash
chain. The same persistence path cannot serve both without dropping
important guarantees.

## Decision
- Typed channels in `internal/bus` for each event kind.
- `findings-persistence` subscriber: buffered goroutine (1000 findings or
  1 s) that flushes with `pgx.CopyFrom`.
- `audit-persistence` subscriber: **single-threaded** goroutine with
  sequential `INSERT` statements. The hash chain cannot be parallelised.
- Other subscribers: `scoring`, `triage`, `web-sse`, `outbox`.

## Consequences
### Positive
- Findings batch throughput is high and predictable.
- Audit chain integrity is trivial to reason about.
- Backpressure is visible via `elsereno_persistence_lag_seconds`.

### Negative / trade-offs
- Two persistence paths to maintain and test.
- A slow audit sink blocks audit-producing operations until drained.

## Alternatives considered
- Single persistence goroutine: kills findings throughput.
- Per-subscriber channels: chosen. Collapsing into one bus would lose
  type safety.

## References
- `internal/bus/`; ADR-015 (JCS hash chain).
