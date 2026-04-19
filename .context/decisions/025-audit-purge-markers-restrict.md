---
id: 025
title: audit_purge_markers.audit_entry_id ON DELETE RESTRICT
status: accepted
date: 2026-04-19
phase: F0
---

# ADR-025: `audit_purge_markers.audit_entry_id ON DELETE RESTRICT`

## Context
`audit_purge_markers` carries the `audit_entry_id` of the corresponding
`purge_event` entry in `audit_log`. If that entry were hard-deleted by
`audit compact`, the marker would point at a non-existent row
(FK violation or orphan — PITF-033).

## Decision
- Declare the FK as `ON DELETE RESTRICT`.
- Reinforce with the rule in ADR-013: `audit compact` **never**
  hard-deletes entries whose `event_type IN ('genesis','chain_rebase',
  'purge_event')`. Metadata entries are chain substrate and outlive
  `compact`.
- Together, these make the FK safe by construction: `compact` cannot
  target the row, so RESTRICT cannot fire.

## Consequences
### Positive
- FK is a guard-rail rather than a footgun.
- Makes retention analysis auditable: `audit_purge_markers` always
  resolves.

### Negative / trade-offs
- A future change to `compact` that relaxes the exclusion rule would hit
  the RESTRICT and fail loudly — exactly what we want.

## Alternatives considered
- `ON DELETE SET NULL`: loses the pointer silently.
- `ON DELETE CASCADE`: deletes the marker when the entry is deleted;
  breaks the audit trail about the purge itself.

## References
- ADR-013; PITF-033.
