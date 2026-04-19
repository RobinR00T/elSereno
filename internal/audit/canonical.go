package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/gowebpki/jcs"
)

// GenesisPrevHash is the prev_hash value of the genesis entry: 32 zero
// bytes (ADR-013, ADR-015).
var GenesisPrevHash = make([]byte, 32)

// Entry is the in-memory representation of an audit row.
type Entry struct {
	ID         int64     // bigserial
	OccurredAt time.Time // TIMESTAMPTZ microseconds (ADR-020)
	Actor      string    // "system" for non-attributable
	EventType  EventType
	Payload    json.RawMessage // JSONB (already JSON-encoded by the writer)
	PrevHash   []byte          // 32 bytes
	EntryHash  []byte          // 32 bytes; derived, EXCLUDED from JCS
}

// CanonicalFields is the exact ordered list of fields fed into JCS.
// This is the source of truth (PITF-014); docs reference it.
var CanonicalFields = []string{"id", "occurred_at", "actor", "event_type", "payload", "prev_hash"}

// Canonicalise returns the JCS-encoded canonical bytes for e. The
// output is stable across Go versions because JCS (RFC 8785) defines
// an exact serialisation.
func Canonicalise(e Entry) ([]byte, error) {
	// Build an ordered JSON object whose keys are exactly
	// CanonicalFields. JCS will re-sort them alphabetically, so the
	// insertion order here is not load-bearing; we set all fields.
	obj := map[string]any{
		"id":          e.ID,
		"occurred_at": e.OccurredAt.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano),
		"actor":       e.Actor,
		"event_type":  string(e.EventType),
		"prev_hash":   hex.EncodeToString(e.PrevHash),
	}
	// Payload is already a JSON value. We want JCS to canonicalise its
	// *value*, not the raw string. If Payload is nil, use {}.
	if len(e.Payload) == 0 {
		obj["payload"] = map[string]any{}
	} else {
		var v any
		if err := json.Unmarshal(e.Payload, &v); err != nil {
			return nil, fmt.Errorf("audit: payload: %w", err)
		}
		obj["payload"] = v
	}

	raw, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("audit: marshal: %w", err)
	}
	return jcs.Transform(raw)
}

// ComputeHash returns SHA-256 over the JCS canonical bytes. It is the
// value persisted as audit_log.entry_hash.
func ComputeHash(e Entry) ([]byte, error) {
	c, err := Canonicalise(e)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(c)
	return sum[:], nil
}

// Verify returns nil when e's stored EntryHash matches the computed
// hash over the canonical form. Returns ErrChainBroken otherwise.
func Verify(e Entry) error {
	got, err := ComputeHash(e)
	if err != nil {
		return err
	}
	if len(e.EntryHash) != len(got) {
		return fmt.Errorf("%w: entry %d", ErrChainBroken, e.ID)
	}
	for i := range got {
		if got[i] != e.EntryHash[i] {
			return fmt.Errorf("%w: entry %d", ErrChainBroken, e.ID)
		}
	}
	return nil
}
