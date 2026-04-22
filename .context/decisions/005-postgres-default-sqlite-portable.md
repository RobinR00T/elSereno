---
id: 005
title: Postgres as the only supported backend (v1.2+)
status: accepted
date: 2026-04-19
phase: F0
updated: 2026-04-22
---

# ADR-005: Postgres as the only supported backend (v1.2+)

## Context
The primary deployment is a single operator on a workstation with a
dedicated Postgres (typically via docker-compose). Field engagements on
air-gapped jump hosts were originally a driver for a portable SQLite
variant, but operator feedback showed the portable variant was rarely
used and added substantial CGO + dual-dialect maintenance cost.

## Decision (v1.2 update)
- Only backend: PostgreSQL ≥ 16 via `pgx/v5` + `pgxpool`.
- The `-tags sqlite` portable variant is REMOVED in v1.2
  (2026-04-22). ADR-012 is superseded.
- Local / offline operators use `docker-compose.dev.yml` for a
  loopback Postgres, or skip the DB entirely (SSE feed + audit
  FileWriter still work without `DATABASE_URL`).
- SQLite is **never** used as an output format.

## Consequences
### Positive
- Deployment flexibility without maintaining two independent data models.
- The default build stays pure-Go and cross-compiles cleanly.

### Negative / trade-offs
- Two SQL dialects to test; migrations under `goose` must stay
  ANSI-friendly or maintain split variants.
- SQLCipher adds a CGO dependency on one variant.

## Alternatives considered
- **Only Postgres**: simpler, but blocks air-gapped usage.
- **Only SQLite**: rules out future multi-user and high-write scenarios.

## References
- Project brief section 5; ADR-012.
