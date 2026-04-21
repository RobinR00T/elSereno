package audit_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"local/elsereno/internal/audit"
)

// fakeConn is a minimal in-memory audit_log store that
// satisfies audit.DBConn. It understands exactly the two queries
// DBWriter issues:
//
//   - SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1
//   - SELECT nextval('audit_log_id_seq')
//   - INSERT INTO audit_log (...) VALUES (...)
//
// Anything else returns a helpful error. Keeping it narrow means
// the fake stays comprehensible; the real SQL is exercised by
// the db_integration build tag (next commit).
type fakeConn struct {
	mu      sync.Mutex
	nextSeq int64
	rows    []audit.Entry
	execErr error
	rowErr  error
}

func newFakeConn() *fakeConn { return &fakeConn{nextSeq: 0} }

func (f *fakeConn) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	f.mu.Lock()
	defer f.mu.Unlock()
	_ = args
	switch {
	case strings.Contains(sql, "nextval('audit_log_id_seq')"):
		f.nextSeq++
		return &fakeRow{val: f.nextSeq}
	case strings.Contains(sql, "ORDER BY id DESC"):
		if f.rowErr != nil {
			return &fakeRow{err: f.rowErr}
		}
		if len(f.rows) == 0 {
			return &fakeRow{err: pgx.ErrNoRows}
		}
		last := f.rows[len(f.rows)-1]
		return &fakeRow{bytes: last.EntryHash}
	}
	return &fakeRow{err: fmt.Errorf("fakeConn: unexpected QueryRow: %s", sql)}
}

func (f *fakeConn) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.execErr != nil {
		return pgconn.CommandTag{}, f.execErr
	}
	if !strings.Contains(sql, "INSERT INTO audit_log") {
		return pgconn.CommandTag{}, fmt.Errorf("fakeConn: unexpected Exec: %s", sql)
	}
	entry, err := fakeInsertArgs(args)
	if err != nil {
		return pgconn.CommandTag{}, err
	}
	f.rows = append(f.rows, entry)
	return pgconn.CommandTag{}, nil
}

// fakeInsertArgs validates the argument layout of the audit_log
// INSERT statement and builds an Entry from it. Keeping the
// assertions in one place makes the fake's expectations
// self-documenting + plays nicely with the forcetypeassert
// linter: every assertion is checked and returns a typed error.
func fakeInsertArgs(args []any) (audit.Entry, error) {
	if len(args) != 7 {
		return audit.Entry{}, fmt.Errorf("fakeConn: want 7 args, got %d", len(args))
	}
	id, ok := args[0].(int64)
	if !ok {
		return audit.Entry{}, fmt.Errorf("arg[0] = %T, want int64", args[0])
	}
	occurred, ok := args[1].(time.Time)
	if !ok {
		return audit.Entry{}, fmt.Errorf("arg[1] = %T, want time.Time", args[1])
	}
	actor, ok := args[2].(string)
	if !ok {
		return audit.Entry{}, fmt.Errorf("arg[2] = %T, want string", args[2])
	}
	event, ok := args[3].(string)
	if !ok {
		return audit.Entry{}, fmt.Errorf("arg[3] = %T, want string", args[3])
	}
	payload, ok := args[4].([]byte)
	if !ok {
		return audit.Entry{}, fmt.Errorf("arg[4] = %T, want []byte", args[4])
	}
	prev, ok := args[5].([]byte)
	if !ok {
		return audit.Entry{}, fmt.Errorf("arg[5] = %T, want []byte", args[5])
	}
	entryHash, ok := args[6].([]byte)
	if !ok {
		return audit.Entry{}, fmt.Errorf("arg[6] = %T, want []byte", args[6])
	}
	return audit.Entry{
		ID:         id,
		OccurredAt: occurred,
		Actor:      actor,
		EventType:  audit.EventType(event),
		Payload:    json.RawMessage(payload),
		PrevHash:   append([]byte(nil), prev...),
		EntryHash:  append([]byte(nil), entryHash...),
	}, nil
}

// fakeRow implements pgx.Row for either an int64 result, a
// []byte result, or an error.
type fakeRow struct {
	val   int64
	bytes []byte
	err   error
}

func (r *fakeRow) Scan(dst ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(dst) != 1 {
		return fmt.Errorf("fakeRow: want 1 dst, got %d", len(dst))
	}
	switch d := dst[0].(type) {
	case *int64:
		*d = r.val
		return nil
	case *[]byte:
		*d = append((*d)[:0], r.bytes...)
		return nil
	default:
		return fmt.Errorf("fakeRow: unsupported dst type %T", dst[0])
	}
}

// TestDBWriter_GenesisAndChain runs the smoke: first Append is
// a genesis entry (PrevHash = zeros), second Append chains to
// the first's entry_hash.
func TestDBWriter_GenesisAndChain(t *testing.T) {
	conn := newFakeConn()
	w := audit.OpenDBWriter(conn)

	e1, err := w.Append(context.Background(), audit.Entry{
		EventType: audit.EventGenesis,
		Actor:     "ci",
		Payload:   json.RawMessage(`{"note":"db-boot"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if e1.ID != 1 {
		t.Fatalf("first ID = %d, want 1", e1.ID)
	}
	for i, b := range e1.PrevHash {
		if b != 0 {
			t.Fatalf("genesis prev_hash[%d] = 0x%02x, want 0", i, b)
		}
	}

	e2, err := w.Append(context.Background(), audit.Entry{
		EventType: audit.EventVaultInit,
		Actor:     "ci",
	})
	if err != nil {
		t.Fatal(err)
	}
	if e2.ID != 2 {
		t.Fatalf("second ID = %d", e2.ID)
	}
	if !bytesEq(e2.PrevHash, e1.EntryHash) {
		t.Fatalf("chain broken: e2.PrevHash != e1.EntryHash")
	}
}

// TestDBWriter_ResumesFromExistingRow simulates opening a
// DBWriter against a table that already has rows. The first
// Append must chain from the seeded row's entry_hash.
func TestDBWriter_ResumesFromExistingRow(t *testing.T) {
	conn := newFakeConn()
	// Pre-seed a row — simulate a prior process's append.
	seed := audit.Entry{
		ID:        17,
		EventType: audit.EventGenesis,
		Actor:     "old",
		Payload:   json.RawMessage(`{}`),
		EntryHash: []byte("seed-hash-32-bytes--------------"),
	}
	conn.rows = append(conn.rows, seed)

	w := audit.OpenDBWriter(conn)
	e, err := w.Append(context.Background(), audit.Entry{
		EventType: audit.EventVaultUnlock,
		Actor:     "ci",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytesEq(e.PrevHash, seed.EntryHash) {
		t.Fatalf("resume: PrevHash = %x, want %x", e.PrevHash, seed.EntryHash)
	}
}

// TestDBWriter_RejectsUnknownEventType mirrors the FileWriter
// contract: the enum is a source of truth, unknown types short-
// circuit before the INSERT.
func TestDBWriter_RejectsUnknownEventType(t *testing.T) {
	conn := newFakeConn()
	w := audit.OpenDBWriter(conn)
	_, err := w.Append(context.Background(), audit.Entry{EventType: "not_real"})
	if !errors.Is(err, audit.ErrBadEventType) {
		t.Fatalf("want ErrBadEventType, got %v", err)
	}
}

// TestDBWriter_ObserverFiresAfterInsert wires the post-append
// observer and checks it gets the filled Entry.
func TestDBWriter_ObserverFiresAfterInsert(t *testing.T) {
	conn := newFakeConn()
	w := audit.OpenDBWriter(conn)
	var got audit.Entry
	w.SetObserver(func(e audit.Entry) { got = e })
	_, err := w.Append(context.Background(), audit.Entry{EventType: audit.EventGenesis})
	if err != nil {
		t.Fatal(err)
	}
	if got.ID == 0 || len(got.EntryHash) != 32 {
		t.Fatalf("observer not called with filled entry: %+v", got)
	}
}

// TestDBWriter_InsertFailurePreservesChain checks that when the
// INSERT errors we do NOT advance `prevHash`. Otherwise a
// subsequent Append would be chained to a hash never persisted.
func TestDBWriter_InsertFailurePreservesChain(t *testing.T) {
	conn := newFakeConn()
	w := audit.OpenDBWriter(conn)
	// First insert succeeds (establishes prev_hash).
	_, _ = w.Append(context.Background(), audit.Entry{EventType: audit.EventGenesis})

	// Make the next Exec fail.
	conn.execErr = errors.New("simulated ETIMEDOUT")
	_, err := w.Append(context.Background(), audit.Entry{EventType: audit.EventVaultInit})
	if err == nil {
		t.Fatal("expected insert failure to surface")
	}
	conn.execErr = nil

	// Chain must still be intact. Next successful Append should
	// chain to the FIRST entry's entry_hash, not to any ghost
	// intermediate.
	first := conn.rows[0]
	next, err := w.Append(context.Background(), audit.Entry{EventType: audit.EventVaultInit})
	if err != nil {
		t.Fatal(err)
	}
	if !bytesEq(next.PrevHash, first.EntryHash) {
		t.Fatalf("chain corrupted: PrevHash=%x want=%x", next.PrevHash, first.EntryHash)
	}
}
