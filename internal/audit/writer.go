package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

// Writer appends entries to the audit chain. Implementations MUST
// be safe for concurrent callers; the package invariant is that
// appends are serialised so each entry's prev_hash equals the
// preceding entry's entry_hash.
type Writer interface {
	// Append computes prev_hash + entry_hash for e and persists it.
	// Returns the entry with ID + EntryHash + PrevHash populated.
	Append(ctx context.Context, e Entry) (Entry, error)
}

// Observer is a post-append hook called once per successfully
// persisted Entry. It runs under the writer mutex so observer
// invocations keep the chain's order; observers MUST be
// non-blocking and MUST NOT panic. The canonical observer is a
// non-blocking `Broadcaster.Publish` that drops on backpressure.
type Observer func(Entry)

// FileWriter persists entries to a JSONL file. One line per entry,
// with the chain invariant enforced in memory + on write. The file
// is opened with O_APPEND so operator tooling (grep, jq, tail) can
// read it while the writer is active.
//
// The file lives at a caller-supplied path (typically
// `~/.elsereno/audit.jsonl` with mode 0600). Concurrent writers
// on the same process are serialised by the struct mutex; cross-
// process concurrency requires a flock, which F7+ adds when a
// multi-operator workflow becomes a real scenario.
type FileWriter struct {
	mu       sync.Mutex
	path     string
	f        *os.File
	nextID   int64
	prevHash []byte

	// observer, if set, is invoked after every successful Append
	// with the final persisted Entry. Used to fan-out into the SSE
	// broadcaster; see `internal/web/stream`.
	observer Observer
}

// SetObserver installs the post-append hook. Pass nil to clear.
// Safe to call before or after Append calls start; the hook is
// guarded by the writer mutex only for the duration of the swap.
func (w *FileWriter) SetObserver(o Observer) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.observer = o
}

// OpenFileWriter opens path for append. If the file is empty, the
// next Append call will produce the genesis entry (PrevHash = 32
// zero bytes, ID = 1). If the file already has entries, the
// writer reads the last line and resumes the chain.
func OpenFileWriter(path string) (*FileWriter, error) {
	// #nosec G304 -- operator-supplied audit-log path
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: open %s: %w", path, err)
	}
	w := &FileWriter{path: path, f: f, prevHash: GenesisPrevHash}
	if err := w.resume(); err != nil {
		_ = f.Close()
		return nil, err
	}
	return w, nil
}

// Close flushes + closes the underlying file. Safe to call
// multiple times.
func (w *FileWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return nil
	}
	err := w.f.Close()
	w.f = nil
	return err
}

// resume reads the existing file (if any) and sets nextID +
// prevHash so the next Append continues the chain.
func (w *FileWriter) resume() error {
	// The append-only layout guarantees the last line is the most
	// recent entry. We can scan forwards — fine for modest
	// audit-log sizes (operator workstations rarely exceed MiB of
	// audit rows in a session).
	// #nosec G304 -- same path we just opened
	data, err := os.ReadFile(w.path)
	if err != nil {
		return fmt.Errorf("audit: resume read: %w", err)
	}
	var last Entry
	have := false
	for len(data) > 0 {
		i := indexByte(data, '\n')
		var line []byte
		if i < 0 {
			line = data
			data = nil
		} else {
			line = data[:i]
			data = data[i+1:]
		}
		if len(line) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			return fmt.Errorf("audit: corrupt line: %w", err)
		}
		last = e
		have = true
	}
	if !have {
		w.nextID = 1
		w.prevHash = GenesisPrevHash
		return nil
	}
	w.nextID = last.ID + 1
	w.prevHash = last.EntryHash
	return nil
}

// indexByte is a tiny wrapper so we don't need the "bytes" import
// solely for one call.
func indexByte(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
}

// ErrBadEventType — the caller passed an event type not in the
// AllEventTypes enum. Catching this at Append time keeps bad data
// out of the chain.
var ErrBadEventType = errors.New("audit: event type not in enum")

// Append implements Writer. It mutates e (sets ID / OccurredAt /
// PrevHash / EntryHash) and returns the updated copy.
func (w *FileWriter) Append(_ context.Context, e Entry) (Entry, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return Entry{}, errors.New("audit: writer closed")
	}
	if !isKnownEventType(e.EventType) {
		return Entry{}, fmt.Errorf("%w: %q", ErrBadEventType, e.EventType)
	}
	if e.Actor == "" {
		e.Actor = "system"
	}
	if e.OccurredAt.IsZero() {
		e.OccurredAt = time.Now().UTC().Truncate(time.Microsecond)
	}
	if len(e.Payload) == 0 {
		e.Payload = []byte("{}")
	}
	e.ID = w.nextID
	e.PrevHash = append([]byte(nil), w.prevHash...)
	hash, err := ComputeHash(e)
	if err != nil {
		return Entry{}, fmt.Errorf("audit: compute: %w", err)
	}
	e.EntryHash = hash
	line, err := json.Marshal(e)
	if err != nil {
		return Entry{}, fmt.Errorf("audit: marshal: %w", err)
	}
	line = append(line, '\n')
	if _, err := w.f.Write(line); err != nil {
		return Entry{}, fmt.Errorf("audit: write: %w", err)
	}
	w.nextID++
	w.prevHash = hash
	obs := w.observer
	if obs != nil {
		// Run under the lock is fine: the contract is "fast"
		// observers. The typical hook is a non-blocking
		// Broadcaster.Publish which drops on backpressure.
		obs(e)
	}
	return e, nil
}

// appendVerbatim persists e without running any chain logic or
// mutating its fields. It is the FileMirror path on a
// MultiWriter: the primary already owns the chain state, and
// the mirror just writes the same row to disk. ID / OccurredAt
// / PrevHash / EntryHash MUST all be set by the caller.
//
// The writer mutex still guards file writes so concurrent
// Mirror calls don't interleave bytes.
func (w *FileWriter) appendVerbatim(_ context.Context, e Entry) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil {
		return errors.New("audit: file writer closed")
	}
	if e.ID == 0 || len(e.EntryHash) != 32 || len(e.PrevHash) != 32 {
		return errors.New("audit: verbatim entry missing id/hashes")
	}
	line, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("audit: verbatim marshal: %w", err)
	}
	line = append(line, '\n')
	if _, err := w.f.Write(line); err != nil {
		return fmt.Errorf("audit: verbatim write: %w", err)
	}
	// Advance local state so a subsequent direct Append (rare
	// in a MultiWriter setup but legal) continues the chain
	// from the mirrored row.
	if e.ID+1 > w.nextID {
		w.nextID = e.ID + 1
	}
	w.prevHash = append([]byte(nil), e.EntryHash...)
	return nil
}

// isKnownEventType checks e against the AllEventTypes enum.
func isKnownEventType(t EventType) bool {
	for _, v := range AllEventTypes {
		if v == t {
			return true
		}
	}
	return false
}

// VerifyFile walks the JSONL file and returns nil when the chain is
// intact end-to-end. Returns a typed error indexing the first
// broken entry otherwise.
func VerifyFile(path string) error {
	// #nosec G304 -- operator-supplied path
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("audit: open %s: %w", path, err)
	}
	prev := GenesisPrevHash
	nextID := int64(1)
	for len(data) > 0 {
		i := indexByte(data, '\n')
		var line []byte
		if i < 0 {
			line = data
			data = nil
		} else {
			line = data[:i]
			data = data[i+1:]
		}
		if len(line) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			return fmt.Errorf("audit: line %d parse: %w", nextID, err)
		}
		if e.ID != nextID {
			return fmt.Errorf("%w: want id=%d got id=%d", ErrChainBroken, nextID, e.ID)
		}
		if !bytesEqual(e.PrevHash, prev) {
			return fmt.Errorf("%w: id=%d prev_hash mismatch", ErrChainBroken, e.ID)
		}
		want, err := ComputeHash(e)
		if err != nil {
			return fmt.Errorf("audit: line %d hash: %w", e.ID, err)
		}
		if !bytesEqual(e.EntryHash, want) {
			return fmt.Errorf("%w: id=%d entry_hash mismatch", ErrChainBroken, e.ID)
		}
		prev = e.EntryHash
		nextID++
	}
	return nil
}

func bytesEqual(a, b []byte) bool {
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
