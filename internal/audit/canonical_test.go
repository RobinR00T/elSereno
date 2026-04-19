package audit_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"local/elsereno/internal/audit"
)

func TestCanonicaliseStable(t *testing.T) {
	t.Parallel()
	e := audit.Entry{
		ID:         1,
		OccurredAt: time.Date(2026, 4, 19, 10, 0, 0, 123456789, time.UTC),
		Actor:      "system",
		EventType:  audit.EventGenesis,
		Payload:    json.RawMessage(`{"scope_hash":"abc","operator":"alice"}`),
		PrevHash:   audit.GenesisPrevHash,
	}
	a, err := audit.Canonicalise(e)
	if err != nil {
		t.Fatalf("Canonicalise: %v", err)
	}
	// Swap to equivalent but differently-ordered payload; JCS must produce the same bytes.
	e2 := e
	e2.Payload = json.RawMessage(`{"operator":"alice","scope_hash":"abc"}`)
	b, err := audit.Canonicalise(e2)
	if err != nil {
		t.Fatalf("Canonicalise: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("JCS is not stable:\n  %s\n  %s", a, b)
	}
}

func TestComputeAndVerify(t *testing.T) {
	t.Parallel()
	e := audit.Entry{
		ID:         42,
		OccurredAt: time.Unix(1_700_000_000, 0).UTC(),
		Actor:      "system",
		EventType:  audit.EventTokenRotate,
		Payload:    json.RawMessage(`{"old_gen":5,"new_gen":6}`),
		PrevHash:   audit.GenesisPrevHash,
	}
	h, err := audit.ComputeHash(e)
	if err != nil {
		t.Fatalf("ComputeHash: %v", err)
	}
	e.EntryHash = h
	if err := audit.Verify(e); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// Tamper with payload; verification must fail with ErrChainBroken.
	e.Payload = json.RawMessage(`{"old_gen":5,"new_gen":99}`)
	if err := audit.Verify(e); !errors.Is(err, audit.ErrChainBroken) {
		t.Fatalf("tampered verify: got %v, want ErrChainBroken", err)
	}
}
