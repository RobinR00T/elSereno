---
id: 005
title: Postgres by default, SQLite portable via -tags sqlite
status: accepted
date: 2026-04-19
phase: F0
---

# ADR-005: Postgres by default, SQLite portable via `-tags sqlite`

## Context
The primary deployment is a single operator on a workstation with a
dedicated Postgres (typically via docker-compose). Field engagements on
air-gapped jump hosts need a no-Docker option.

## Decision
- Default backend: PostgreSQL ≥ 16 via `pgx/v5` + `pgxpool`.
- Portable backend: SQLCipher via `github.com/mutecomm/go-sqlcipher/v4`
  behind `-tags sqlite`, which requires `CGO_ENABLED=1` and builds only for
  the native architecture of the runner (ADR-012, PITF-006).
- SQLite is **never** used as an output format — only as an optional
  runtime backend.

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
