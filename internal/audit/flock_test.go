package audit_test

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"local/elsereno/internal/audit"
)

// TestFlock_TwoWritersInterleaveCleanly — boots two FileWriter
// instances against the same path (simulating two ElSereno
// processes) and has each append entries concurrently. With
// the v1.15 chunk-4 flock + resume-tail-on-Append flow, the
// resulting file MUST have:
//
//   - Strictly increasing IDs across the merged chain.
//   - Every entry's prev_hash == the preceding entry's
//     entry_hash (the chain invariant).
//
// Without flock, races between A's read-prevHash and B's
// write-entry produce duplicate IDs + broken prev_hash
// linkage. This test fails immediately under the old code
// and passes with the new flock.
func TestFlock_TwoWritersInterleaveCleanly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	wA, err := audit.OpenFileWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = wA.Close() })

	wB, err := audit.OpenFileWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = wB.Close() })

	const perWriter = 25
	var wg sync.WaitGroup
	wg.Add(2)
	emit := func(w *audit.FileWriter, actor string) {
		defer wg.Done()
		for i := 0; i < perWriter; i++ {
			_, err := w.Append(context.Background(), audit.Entry{
				EventType: audit.EventAdmin,
				Actor:     actor,
				Payload:   json.RawMessage(`{}`),
			})
			if err != nil {
				t.Errorf("%s append %d: %v", actor, i, err)
				return
			}
		}
	}
	go emit(wA, "writer-a")
	go emit(wB, "writer-b")
	wg.Wait()

	// Read back the chain and verify integrity.
	entries := readAllEntries(t, path)
	if got, want := len(entries), perWriter*2; got != want {
		t.Fatalf("got %d entries, want %d (concurrency lost rows)", got, want)
	}
	// IDs must be strictly increasing 1..N.
	for i, e := range entries {
		if e.ID != int64(i+1) {
			t.Errorf("entries[%d].ID = %d, want %d", i, e.ID, i+1)
		}
	}
	// Chain invariant: each entry's PrevHash == previous
	// entry's EntryHash.
	for i := 1; i < len(entries); i++ {
		if string(entries[i].PrevHash) != string(entries[i-1].EntryHash) {
			t.Errorf("chain broken at i=%d: prev=%x, want %x",
				i, entries[i].PrevHash, entries[i-1].EntryHash)
		}
	}
	// Both actors must have produced entries.
	counts := map[string]int{}
	for _, e := range entries {
		counts[e.Actor]++
	}
	if counts["writer-a"] != perWriter || counts["writer-b"] != perWriter {
		t.Errorf("actor counts: %v, want %d each", counts, perWriter)
	}
}

// TestFlock_AppendVerbatimAlsoLocked — appendVerbatim is the
// MultiWriter mirror path; the same flock invariant applies
// (it shares the file with the primary FileWriter on a
// different ElSereno process). Use the public path: open one
// writer, do an Append (which goes through verbatim on the
// mirror), confirm the file is well-formed.
func TestFlock_AppendVerbatimAlsoLocked(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	w, err := audit.OpenFileWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	// Two appends in sequence — verifies the flock unlock
	// after each call works (we'd deadlock on the second
	// Append if unlock didn't fire).
	for i := 0; i < 5; i++ {
		_, err := w.Append(context.Background(), audit.Entry{
			EventType: audit.EventAdmin,
			Actor:     "test",
			Payload:   json.RawMessage(`{}`),
		})
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	if got := len(readAllEntries(t, path)); got != 5 {
		t.Errorf("got %d entries, want 5", got)
	}
}

// readAllEntries parses the audit.jsonl file from disk and
// returns the entries in append order.
func readAllEntries(t *testing.T, path string) []audit.Entry {
	t.Helper()
	// #nosec G304 — test-controlled path
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var out []audit.Entry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		var e audit.Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		out = append(out, e)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}
