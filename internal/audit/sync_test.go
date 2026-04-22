package audit_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"local/elsereno/internal/audit"
)

// captureMirror records every entry passed to Mirror. Implements
// audit.MirrorWriter.
type captureMirror struct {
	entries []audit.Entry
	err     error
}

func (c *captureMirror) Mirror(_ context.Context, e audit.Entry) error {
	if c.err != nil {
		return c.err
	}
	c.entries = append(c.entries, e)
	return nil
}

// seedFile writes a valid 3-entry chain using FileWriter and
// returns the path. Each test uses this to get a realistic
// source of truth.
func seedFile(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	w, err := audit.OpenFileWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	for _, e := range []audit.Entry{
		{EventType: audit.EventGenesis, Actor: "boot"},
		{EventType: audit.EventVaultInit, Actor: "op", Payload: json.RawMessage(`{"note":"init"}`)},
		{EventType: audit.EventVaultUnlock, Actor: "op"},
	} {
		if _, err := w.Append(context.Background(), e); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func TestSyncFromFile_ImportsAllEntries(t *testing.T) {
	path := seedFile(t)
	mir := &captureMirror{}
	n, err := audit.SyncFromFile(context.Background(), path, mir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("imported = %d, want 3", n)
	}
	if len(mir.entries) != 3 {
		t.Fatalf("captured = %d, want 3", len(mir.entries))
	}
	// IDs preserved.
	for i, e := range mir.entries {
		if int(e.ID) != i+1 {
			t.Fatalf("entries[%d].ID = %d, want %d", i, e.ID, i+1)
		}
	}
}

func TestSyncFromFile_SkipsExistingIDs(t *testing.T) {
	path := seedFile(t)
	mir := &captureMirror{}
	// Pretend ID 1 already exists in target.
	existing := func(_ context.Context, id int64) (bool, error) {
		return id == 1, nil
	}
	n, err := audit.SyncFromFile(context.Background(), path, mir, existing)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("imported = %d, want 2 (ID 1 skipped)", n)
	}
	if mir.entries[0].ID != 2 {
		t.Fatalf("first captured ID = %d, want 2", mir.entries[0].ID)
	}
}

func TestSyncFromFile_DetectsTamperedPrevHash(t *testing.T) {
	path := seedFile(t)
	// Corrupt a byte inside entry 2's JSON payload so either
	// prev_hash or entry_hash re-computation fails.
	raw, err := os.ReadFile(path) //nolint:gosec // G304 — path from t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	// Find the first newline, flip a byte a few chars into line 2.
	i := 0
	for ; i < len(raw); i++ {
		if raw[i] == '\n' {
			raw[i+5] ^= 0xFF
			break
		}
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil { //nolint:gosec // G306 — path from t.TempDir(); 0600 OK
		t.Fatal(err)
	}

	mir := &captureMirror{}
	_, err = audit.SyncFromFile(context.Background(), path, mir, nil)
	if err == nil {
		t.Fatal("expected chain-broken error on tampered file")
	}
}
