---
id: 023
title: `audit_log.event_type` is a SQL CHECK enumeration; DDL is the source of truth
status: accepted
date: 2026-04-19
phase: F0
---

# ADR-023: `audit_log.event_type` is a SQL CHECK enumeration; DDL is the source of truth

## Context
Event types are enumerated in the DDL, referenced in Go code, documented
in `.context/persistence.md` and the CHANGELOG. Drift between these four
surfaces is a known hazard (PITF-030, PITF-022).

## Decision
- The **source of truth** for the event-type enumeration is the SQL
  `CHECK` constraint in migration 00001 (`internal/db/migrations/
  00001_initial.sql`).
- Go constants in `internal/audit/` mirror the DDL list; a unit test
  asserts they remain in sync with the migration file.
- Documentation references are derivative and marked as such.

## Consequences
### Positive
- A single file — the migration — defines the allowed set.
- Silent drift becomes a hard CI failure via the mirror-check test.

### Negative / trade-offs
- Changes to the enumeration require a migration and a Go update; a small
  friction that matches the policy cost of changing audit semantics.

## Alternatives considered
- Go constants as source of truth: then the DDL diverges silently on
  manual migration runs.

## References
- PITF-022, PITF-030; migrations/00001.
