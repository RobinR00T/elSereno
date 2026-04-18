package audit

import "errors"

// ErrChainBroken indicates that the audit chain failed verification:
// a computed entry_hash did not match the stored one, or a prev_hash
// did not match the previous entry_hash. It lives in this package
// (PITF-009) because it is specific to the audit subsystem.
var ErrChainBroken = errors.New("audit: hash chain broken")

// ErrCompactProtectedEntry is returned when a compact() call tries to
// remove an entry whose event_type is in {genesis, chain_rebase,
// purge_event}. Callers must skip those rows (ADR-013, ADR-025).
var ErrCompactProtectedEntry = errors.New("audit: refused to compact protected metadata entry")
