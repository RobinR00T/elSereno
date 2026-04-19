---
id: 020
title: Timestamps RFC 3339 with up to 6 fractional digits (microseconds)
status: accepted
date: 2026-04-19
phase: F0
---

# ADR-020: Timestamps RFC 3339 with up to 6 fractional digits (microseconds)

## Context
Postgres `TIMESTAMPTZ` stores microsecond precision. A spec that talks
about "nanoseconds" (Go's native `time.Time` resolution) would truncate
silently on write and produce non-round-tripping serialisations
(PITF-024).

## Decision
- All on-wire timestamps are RFC 3339 with **up to 6 fractional digits**.
- Storage in Postgres `TIMESTAMPTZ` is authoritative.
- The Go side truncates to microseconds before serialisation (explicit
  `t.Truncate(time.Microsecond)`).

## Consequences
### Positive
- Round-tripping is exact.
- No surprise truncations between in-memory values, JSON, and DB.

### Negative / trade-offs
- Fuzz-equality tests that compare pre- and post-DB timestamps must
  truncate first.

## Alternatives considered
- RFC 3339 nanoseconds: loses information on write to Postgres.
- Unix-millis: human-unfriendly; loses sub-ms resolution.

## References
- PITF-024; `.context/persistence.md`.
