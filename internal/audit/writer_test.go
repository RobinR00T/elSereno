package audit_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"local/elsereno/internal/audit"
)

func TestFileWriter_GenesisPlusAppend(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	w, err := audit.OpenFileWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })

	e1, err := w.Append(context.Background(), audit.Entry{
		EventType: audit.EventGenesis,
		Actor:     "system",
		Payload:   json.RawMessage(`{"note":"genesis"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if e1.ID != 1 {
		t.Fatalf("ID: %d, want 1", e1.ID)
	}
	if !bytesEq(e1.PrevHash, audit.GenesisPrevHash) {
		t.Fatalf("genesis prev_hash must be all zeros; got %x", e1.PrevHash)
	}

	e2, err := w.Append(context.Background(), audit.Entry{
		EventType: audit.EventVaultInit,
		Actor:     "danielsolisagea",
		Payload:   json.RawMessage(`{"path":"/tmp/vault"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if e2.ID != 2 {
		t.Fatalf("second entry ID: %d", e2.ID)
	}
	if !bytesEq(e2.PrevHash, e1.EntryHash) {
		t.Fatalf("second prev_hash must equal first entry_hash")
	}

	// Verify round-trip.
	if err := audit.VerifyFile(path); err != nil {
		t.Fatalf("VerifyFile: %v", err)
	}
}

func TestFileWriter_Resume(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	// First session.
	w, err := audit.OpenFileWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = w.Append(context.Background(), audit.Entry{EventType: audit.EventGenesis})
	e2, err := w.Append(context.Background(), audit.Entry{EventType: audit.EventVaultUnlock})
	if err != nil {
		t.Fatal(err)
	}
	_ = w.Close()

	// Second session: should continue from ID=3.
	w2, err := audit.OpenFileWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w2.Close() })
	e3, err := w2.Append(context.Background(), audit.Entry{EventType: audit.EventVaultLock})
	if err != nil {
		t.Fatal(err)
	}
	if e3.ID != 3 {
		t.Fatalf("resume ID: %d", e3.ID)
	}
	if !bytesEq(e3.PrevHash, e2.EntryHash) {
		t.Fatalf("resume must chain to previous session's last entry_hash")
	}
	if err := audit.VerifyFile(path); err != nil {
		t.Fatalf("VerifyFile after resume: %v", err)
	}
}

func TestFileWriter_RejectsUnknownEventType(t *testing.T) {
	dir := t.TempDir()
	w, err := audit.OpenFileWriter(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	_, err = w.Append(context.Background(), audit.Entry{EventType: "not_real"})
	if !errors.Is(err, audit.ErrBadEventType) {
		t.Fatalf("want ErrBadEventType, got %v", err)
	}
}

func TestVerifyFile_DetectsTamper(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	w, _ := audit.OpenFileWriter(path)
	_, _ = w.Append(context.Background(), audit.Entry{EventType: audit.EventGenesis})
	_, _ = w.Append(context.Background(), audit.Entry{EventType: audit.EventVaultInit})
	_ = w.Close()

	// Flip a byte in the payload of entry 2.
	data, _ := os.ReadFile(path) //nolint:gosec // G304 — path comes from t.TempDir()
	// Find the second newline and corrupt a byte after it.
	nl1 := 0
	for i, b := range data {
		if b == '\n' {
			nl1 = i + 1
			break
		}
	}
	data[nl1+5] ^= 0x01
	_ = os.WriteFile(path, data, 0o600) //nolint:gosec // G306/G703 — path from t.TempDir(), mode is 0600

	if err := audit.VerifyFile(path); err == nil {
		t.Fatal("VerifyFile should detect corruption")
	}
}

func TestVerifyFile_EmptyOk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.jsonl")
	// #nosec G306 -- test fixture
	_ = os.WriteFile(path, nil, 0o600)
	if err := audit.VerifyFile(path); err != nil {
		t.Fatalf("empty file should verify ok: %v", err)
	}
}

func bytesEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
