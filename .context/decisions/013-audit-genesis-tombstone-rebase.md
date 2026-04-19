---
id: 013
title: Audit log — genesis, tombstone purge, and chain rebase
status: accepted
date: 2026-04-19
phase: F0
---

# ADR-013: Audit log — genesis, tombstone purge, and chain rebase

## Context
An append-only auditable log needs a well-defined start point, a way to
remove forensically sensitive payloads without breaking integrity, and a
way to hard-delete aged data while declaring the break.

## Decision
- The chain starts with a `genesis` entry whose `prev_hash` is 32 zero
  bytes (`0x00..00`), `actor='system'`, `event_type='genesis'`.
- `elsereno audit purge --before=<date>
  --i-understand-this-is-forensic-data` performs a **tombstone purge**:
  entries remain, `payload_tombstoned=TRUE`, the payload is cleared. The
  chain is preserved. A `purge_event` entry is appended with a manifest
  of what was tombstoned, and a row is written to `audit_purge_markers`.
- `elsereno audit compact --before=<date> --i-break-the-chain` performs a
  **hard delete** of eligible rows and inserts a `chain_rebase` marker
  pointing at the last pre-delete hash. The next entry has
  `prev_hash = hash(rebase_marker)`.
- **Metadata entries are never hard-deleted**: `compact` skips rows where
  `event_type IN ('genesis','chain_rebase','purge_event')`. This makes
  the `ON DELETE RESTRICT` on `audit_purge_markers.audit_entry_id`
  (ADR-025, PITF-033) safe.
- Both commands have batch mode (`--yes` + risk flag) and interactive
  double prompt (PITF-015).

## Consequences
### Positive
- Tombstones let GDPR-triggered removals happen without breaking the
  chain.
- Compaction is auditable: the rebase marker is itself in the chain.
- Metadata-skip rule removes the FK violation class entirely.

### Negative / trade-offs
- Two removal paths to teach and document.
- Operators need to understand the difference between tombstone and
  compact.

## Alternatives considered
- Hard-delete only: loses forensic chain entirely.
- Tombstone only: cannot reclaim storage from aged data.

## References
- ADR-015, ADR-025; PITF-014, PITF-015, PITF-033.
