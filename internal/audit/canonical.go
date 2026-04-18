package audit

import (
	"crypto/sha256"
	"time"
)

// GenesisPrevHash is the prev_hash value of the genesis entry: 32 zero
// bytes (ADR-013, ADR-015).
var GenesisPrevHash = make([]byte, 32)

// Entry is the in-memory representation of an audit row.
type Entry struct {
	ID         int64     // bigserial
	OccurredAt time.Time // stored as TIMESTAMPTZ microseconds (ADR-020)
	Actor      string    // "system" for non-attributable
	EventType  EventType
	Payload    []byte // JSONB, JCS-friendly in itself; see encode below.
	PrevHash   []byte // 32 bytes
	EntryHash  []byte // 32 bytes, derived (EXCLUDED from JCS)
}

// CanonicalFields is the exact ordered list of fields fed into JCS. It
// is enumerated in one place (PITF-014).
var CanonicalFields = []string{"id", "occurred_at", "actor", "event_type", "payload", "prev_hash"}

// computeEntryHash is a placeholder for the real JCS-based hash. In F0
// we emit a deterministic SHA-256 over a simple pipe-delimited encoding
// to keep the scaffold stdlib-only. The JCS implementation lands with
// internal/audit's F1 rewrite; the test harness will flip behind a
// feature flag during migration.
func computeEntryHash(e Entry) []byte {
	h := sha256.New()
	_, _ = h.Write([]byte(CanonicalFields[0]))
	_, _ = h.Write([]byte{':'})
	// id
	_, _ = h.Write(i64Bytes(e.ID))
	_, _ = h.Write([]byte{'|'})
	_, _ = h.Write([]byte(CanonicalFields[1]))
	_, _ = h.Write([]byte{':'})
	_, _ = h.Write([]byte(e.OccurredAt.UTC().Format(time.RFC3339Nano)))
	_, _ = h.Write([]byte{'|'})
	_, _ = h.Write([]byte(CanonicalFields[2]))
	_, _ = h.Write([]byte{':'})
	_, _ = h.Write([]byte(e.Actor))
	_, _ = h.Write([]byte{'|'})
	_, _ = h.Write([]byte(CanonicalFields[3]))
	_, _ = h.Write([]byte{':'})
	_, _ = h.Write([]byte(e.EventType))
	_, _ = h.Write([]byte{'|'})
	_, _ = h.Write([]byte(CanonicalFields[4]))
	_, _ = h.Write([]byte{':'})
	_, _ = h.Write(e.Payload)
	_, _ = h.Write([]byte{'|'})
	_, _ = h.Write([]byte(CanonicalFields[5]))
	_, _ = h.Write([]byte{':'})
	_, _ = h.Write(e.PrevHash)
	return h.Sum(nil)
}

// i64Bytes renders an int64 as its decimal ASCII bytes.
func i64Bytes(v int64) []byte {
	// Stdlib strconv is stdlib; fine to use.
	// Keeping a tiny impl here avoids the strconv import clutter.
	if v == 0 {
		return []byte{'0'}
	}
	neg := v < 0
	if neg {
		v = -v
	}
	buf := make([]byte, 0, 20)
	for v > 0 {
		buf = append([]byte{byte('0' + v%10)}, buf...)
		v /= 10
	}
	if neg {
		buf = append([]byte{'-'}, buf...)
	}
	return buf
}

// ComputeHash wraps computeEntryHash; exported to allow callers to
// verify a single entry without reflection.
func ComputeHash(e Entry) []byte { return computeEntryHash(e) }
