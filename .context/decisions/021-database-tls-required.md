---
id: 021
title: `database.tls_required` ∈ {auto, always, disable}
status: accepted
date: 2026-04-19
phase: F0
---

# ADR-021: `database.tls_required` ∈ {auto, always, disable}

## Context
The dev docker-compose runs Postgres with trust auth on a loopback bind
(`127.0.0.1:5433`). Prod deployments must require TLS. The config needs
to express "safe default per environment" without a runtime surprise.

## Decision
- `database.tls_required` is an enum-like with three values:
  - `auto` (default): TLS required unless the host is loopback
    (`127.0.0.1`, `::1`).
  - `always`: TLS required regardless of host.
  - `disable`: TLS disabled; **rejected at runtime if the host is not
    loopback**.
- The validator rejects any other value (PITF-022).

## Consequences
### Positive
- Right default for dev and prod without surprises.
- Explicit opt-in for insecure configurations.

### Negative / trade-offs
- Operators must understand the three values; documented in `man 5
  elsereno.yaml`.

## Alternatives considered
- Boolean flag: cannot express "auto".
- Four or more values (e.g. `prefer`): overengineered for the need.

## References
- PITF-022; `.context/persistence.md`.
