package audit

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// DBConn is the narrow pgx surface DBWriter needs. Both
// `*pgxpool.Pool` and `*pgx.Conn` satisfy it, and a test can
// implement it in ~30 lines to run DBWriter tests without a
// real Postgres.
type DBConn interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// DBWriter persists audit entries to Postgres while maintaining
// the same chain invariant as FileWriter. ADR-008 requires audit
// appends to be serialised end-to-end — the struct mutex
// enforces that, so a pool with MaxConns>1 is still safe (every
// Append serialises through a single goroutine).
//
// Chain continuity: on first Append, DBWriter queries the most
// recent row and seeds `prevHash` from `entry_hash`. Subsequent
// Appends chain from that value. An empty table starts from
// `GenesisPrevHash` (32 zero bytes) exactly like FileWriter.
//
// ID continuity: DBWriter does NOT let Postgres assign the
// BIGSERIAL automatically — it pulls `nextval` from the
// sequence, uses that ID in the hash, and INSERTs with the
// explicit ID. This means a single Append is two SQL
// round-trips; the mutex keeps them together.
type DBWriter struct {
	mu       sync.Mutex
	conn     DBConn
	prevHash []byte
	resumed  bool // lazy: we chain-resume on first Append, not in the constructor
	observer Observer
}

// OpenDBWriter returns a DBWriter backed by conn. The chain is
// not resumed here; the first call to Append reads the most
// recent row and seeds prevHash. Lazy resume matters because
// callers often construct multiple writers up-front but only
// exercise one per request.
func OpenDBWriter(conn DBConn) *DBWriter {
	return &DBWriter{conn: conn}
}

// SetObserver installs the post-append hook. Mirrors
// FileWriter.SetObserver so a caller can swap between writers
// without changing the observer-wiring code.
func (w *DBWriter) SetObserver(o Observer) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.observer = o
}

// Append implements Writer. The body mirrors FileWriter.Append
// so chain semantics match byte-for-byte: same default Actor,
// same OccurredAt clamp, same empty-payload fallback, same hash
// algorithm. The only difference is the persistence layer.
func (w *DBWriter) Append(ctx context.Context, e Entry) (Entry, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !isKnownEventType(e.EventType) {
		return Entry{}, fmt.Errorf("%w: %q", ErrBadEventType, e.EventType)
	}
	if err := w.resumeIfNeeded(ctx); err != nil {
		return Entry{}, err
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

	// Reserve the ID via the sequence so we can include it in the
	// JCS canonical form BEFORE the INSERT. Letting Postgres pick
	// it via DEFAULT would force a 2-phase INSERT+UPDATE that
	// risks a chain gap if the second statement fails.
	var nextID int64
	if err := w.conn.QueryRow(ctx, `SELECT nextval('audit_log_id_seq')`).Scan(&nextID); err != nil {
		return Entry{}, fmt.Errorf("audit: reserve id: %w", err)
	}
	e.ID = nextID
	e.PrevHash = append([]byte(nil), w.prevHash...)
	hash, err := ComputeHash(e)
	if err != nil {
		return Entry{}, fmt.Errorf("audit: compute: %w", err)
	}
	e.EntryHash = hash

	_, err = w.conn.Exec(ctx, `
		INSERT INTO audit_log (id, occurred_at, actor, event_type, payload, prev_hash, entry_hash)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		e.ID, e.OccurredAt, e.Actor, string(e.EventType),
		[]byte(e.Payload), e.PrevHash, e.EntryHash)
	if err != nil {
		return Entry{}, fmt.Errorf("audit: insert: %w", err)
	}

	w.prevHash = hash
	obs := w.observer
	if obs != nil {
		obs(e)
	}
	return e, nil
}

// appendVerbatim is the DBMirror path on a MultiWriter. It
// persists e without recomputing the chain. The caller is the
// primary Writer and has already assigned the ID / hashes; our
// job is to INSERT the row and advance local `prevHash` so a
// subsequent direct Append continues the chain.
func (w *DBWriter) appendVerbatim(ctx context.Context, e Entry) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if e.ID == 0 || len(e.EntryHash) != 32 || len(e.PrevHash) != 32 {
		return errors.New("audit: verbatim entry missing id/hashes")
	}
	_, err := w.conn.Exec(ctx, `
		INSERT INTO audit_log (id, occurred_at, actor, event_type, payload, prev_hash, entry_hash)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		e.ID, e.OccurredAt, e.Actor, string(e.EventType),
		[]byte(e.Payload), e.PrevHash, e.EntryHash)
	if err != nil {
		return fmt.Errorf("audit: verbatim insert: %w", err)
	}
	w.prevHash = append([]byte(nil), e.EntryHash...)
	w.resumed = true
	return nil
}

// resumeIfNeeded queries the most recent audit_log row and seeds
// prevHash. Empty table → GenesisPrevHash. Called once per
// DBWriter lifetime, guarded by `resumed`.
func (w *DBWriter) resumeIfNeeded(ctx context.Context) error {
	if w.resumed {
		return nil
	}
	var entryHash []byte
	row := w.conn.QueryRow(ctx, `SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1`)
	err := row.Scan(&entryHash)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		w.prevHash = append([]byte(nil), GenesisPrevHash...)
	case err != nil:
		return fmt.Errorf("audit: resume chain: %w", err)
	default:
		w.prevHash = entryHash
	}
	w.resumed = true
	return nil
}
