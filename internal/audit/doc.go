// Package audit implements ElSereno's hash-chained audit log.
//
// The chain uses JCS (RFC 8785) canonicalisation over the fields
// {id, occurred_at, actor, event_type, payload, prev_hash}. entry_hash
// is SHA-256 over those canonical bytes (ADR-015, PITF-014). The genesis
// entry has prev_hash = 0x00..00 (32 zero bytes).
//
// Two removal operations exist (ADR-013):
//
//   - audit purge:   tombstone; payload cleared, row and hashes kept.
//     Writes a purge_event entry and a row in audit_purge_markers.
//   - audit compact: hard-delete with an auditable chain_rebase marker.
//     Never removes entries with event_type in
//     {genesis, chain_rebase, purge_event}; that rule
//     makes ON DELETE RESTRICT on
//     audit_purge_markers.audit_entry_id safe
//     (ADR-025, PITF-033).
//
// The set of allowed event_type values is enumerated in both the SQL
// CHECK constraint (source of truth, migration 00001) and the Go
// constants below; a unit test enforces that they remain in sync
// (ADR-023, PITF-030).
package audit
