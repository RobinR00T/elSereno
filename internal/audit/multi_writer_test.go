package audit_test

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"local/elsereno/internal/audit"
)

// TestMultiWriter_PrimaryFilePlusDBMirror uses the file as the
// primary chain owner and the fake DB as the mirror. Every
// appended row must land in both, with identical hashes.
func TestMultiWriter_PrimaryFilePlusDBMirror(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	fw, err := audit.OpenFileWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fw.Close() })

	conn := newFakeConn()
	dw := audit.OpenDBWriter(conn)

	mw, err := audit.NewMultiWriter(fw, audit.NewDBMirror(dw))
	if err != nil {
		t.Fatal(err)
	}

	entries := []audit.EventType{
		audit.EventGenesis,
		audit.EventVaultInit,
		audit.EventVaultUnlock,
	}
	var ids []int64
	for _, et := range entries {
		e, err := mw.Append(context.Background(), audit.Entry{
			EventType: et,
			Actor:     "ci",
			Payload:   json.RawMessage(`{"k":"v"}`),
		})
		if err != nil {
			t.Fatalf("Append(%s): %v", et, err)
		}
		ids = append(ids, e.ID)
	}

	// Primary chain must verify.
	if err := audit.VerifyFile(path); err != nil {
		t.Fatalf("primary VerifyFile: %v", err)
	}
	// Mirror must have the same rows.
	if len(conn.rows) != len(entries) {
		t.Fatalf("mirror row count = %d, want %d", len(conn.rows), len(entries))
	}
	for i, row := range conn.rows {
		if row.ID != ids[i] {
			t.Fatalf("mirror row[%d].ID = %d, primary gave %d", i, row.ID, ids[i])
		}
	}
}

// TestMultiWriter_PrimaryDBPlusFileMirror exercises the
// opposite pairing: DB is primary, file is mirror. Same
// invariant — both sinks agree on IDs + hashes.
func TestMultiWriter_PrimaryDBPlusFileMirror(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	fw, err := audit.OpenFileWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fw.Close() })

	conn := newFakeConn()
	dw := audit.OpenDBWriter(conn)

	mw, err := audit.NewMultiWriter(dw, audit.NewFileMirror(fw))
	if err != nil {
		t.Fatal(err)
	}

	_, err = mw.Append(context.Background(), audit.Entry{EventType: audit.EventGenesis})
	if err != nil {
		t.Fatal(err)
	}
	_, err = mw.Append(context.Background(), audit.Entry{EventType: audit.EventVaultInit})
	if err != nil {
		t.Fatal(err)
	}

	if len(conn.rows) != 2 {
		t.Fatalf("DB rows = %d, want 2", len(conn.rows))
	}
	if err := audit.VerifyFile(path); err != nil {
		t.Fatalf("mirror VerifyFile: %v", err)
	}
}

// TestMultiWriter_PrimaryErrorHaltsFanout checks that when the
// primary fails, no mirror is touched — we don't want a mirror
// to hold a row the primary doesn't have (would make the
// dashboard show a "ghost" row).
func TestMultiWriter_PrimaryErrorHaltsFanout(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	fw, _ := audit.OpenFileWriter(path)
	_ = fw.Close() // primary will reject appends now

	conn := newFakeConn()
	dw := audit.OpenDBWriter(conn)

	mw, err := audit.NewMultiWriter(fw, audit.NewDBMirror(dw))
	if err != nil {
		t.Fatal(err)
	}
	_, err = mw.Append(context.Background(), audit.Entry{EventType: audit.EventGenesis})
	if err == nil {
		t.Fatal("expected error when primary is closed")
	}
	if len(conn.rows) != 0 {
		t.Fatalf("mirror received %d rows despite primary error", len(conn.rows))
	}
}

// TestMultiWriter_MirrorErrorReportsButKeepsPrimary: if a mirror
// fails, the primary row is already committed. We must surface
// the error to the caller so they know the mirror is stale, but
// we must NOT try to undo the primary insert (that'd corrupt
// the chain).
func TestMultiWriter_MirrorErrorReportsButKeepsPrimary(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	fw, _ := audit.OpenFileWriter(path)
	t.Cleanup(func() { _ = fw.Close() })

	conn := newFakeConn()
	conn.execErr = errors.New("mirror down")
	dw := audit.OpenDBWriter(conn)

	mw, _ := audit.NewMultiWriter(fw, audit.NewDBMirror(dw))
	_, err := mw.Append(context.Background(), audit.Entry{EventType: audit.EventGenesis})
	if err == nil {
		t.Fatal("expected mirror-failure error")
	}
	if !strings.Contains(err.Error(), "mirror") {
		t.Fatalf("error should name the mirror: %v", err)
	}
	// Primary MUST have the row despite mirror failure.
	if err := audit.VerifyFile(path); err != nil {
		t.Fatalf("primary chain broken after mirror failure: %v", err)
	}
}

func TestNewMultiWriter_RejectsNilPrimary(t *testing.T) {
	_, err := audit.NewMultiWriter(nil)
	if err == nil {
		t.Fatal("expected error for nil primary")
	}
}
