package audit

import (
	"crypto/hmac"
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

// computeHash returns the entry's chain hash over the JCS canonical
// bytes. With a non-empty macKey it is HMAC-SHA256(macKey, JCS(e)),
// which is tamper-proof: an attacker with write access to the log but
// without the vault-derived key cannot forge it, so they cannot
// recompute the chain forward after editing an entry. With an empty
// key it is plain SHA-256(JCS(e)), tamper-evident only; used where the
// vault is not unlocked (e.g. read-only harvest).
//
// A single audit log may interleave keyed and unkeyed entries (harvest
// runs without the vault, offensive-write runs with it). The prev_hash
// linkage still protects the unkeyed ones: every keyed entry's HMAC
// covers its prev_hash, i.e. the previous entry's entry_hash, so
// tampering with ANY earlier entry (keyed or not) changes its hash,
// which breaks the next keyed entry's prev_hash, which the attacker
// cannot recompute. The chain is thus tamper-proof up to the last
// keyed entry.
func computeHash(macKey []byte, e Entry) ([]byte, error) {
	c, err := Canonicalise(e)
	if err != nil {
		return nil, err
	}
	if len(macKey) == 0 {
		sum := sha256.Sum256(c)
		return sum[:], nil
	}
	mac := hmac.New(sha256.New, macKey)
	_, _ = mac.Write(c) // hash.Hash.Write never errors
	return mac.Sum(nil), nil
}

// ComputeHash returns the unkeyed SHA-256 hash over the JCS canonical
// bytes. Retained for callers and tests that do not carry a MAC key;
// keyed writers use the internal computeHash with their key.
func ComputeHash(e Entry) ([]byte, error) {
	return computeHash(nil, e)
}

// Verify returns nil when e's stored EntryHash matches the unkeyed
// (SHA-256) hash. Returns ErrChainBroken otherwise. Keyed entries are
// verified via verifyEntry with the vault key.
func Verify(e Entry) error {
	return verifyEntry(nil, e)
}

// verifyEntry checks e.EntryHash against the recomputed hash. With a
// key it accepts an entry that matches EITHER the HMAC (a keyed entry)
// OR plain SHA-256 (a legacy / no-vault entry sharing the same chain);
// the caller's prev_hash linkage check is what makes a downgraded keyed
// entry detectable at the next keyed entry. With an empty key only the
// SHA-256 form is accepted, so keyed entries need the vault to verify.
// Comparisons are constant-time.
func verifyEntry(macKey []byte, e Entry) error {
	if len(macKey) > 0 {
		want, err := computeHash(macKey, e)
		if err != nil {
			return err
		}
		if hmac.Equal(e.EntryHash, want) {
			return nil
		}
	}
	sha, err := computeHash(nil, e)
	if err != nil {
		return err
	}
	if hmac.Equal(e.EntryHash, sha) {
		return nil
	}
	return fmt.Errorf("%w: entry %d", ErrChainBroken, e.ID)
}
