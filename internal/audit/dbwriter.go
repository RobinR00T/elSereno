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

// txBeginner is the optional pgx-pool surface DBWriter uses for the
// cross-process advisory-lock append path. *pgxpool.Pool satisfies it;
// the unit-test fakeConn does not, so tests fall back to the unlocked
// path (single-process, serialised by the struct mutex).
type txBeginner interface {
	BeginTx(ctx context.Context, opts pgx.TxOptions) (pgx.Tx, error)
}

// queryRower is the read surface readLatestHash needs; both DBConn and
// pgx.Tx satisfy it.
type queryRower interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// auditChainLockKey is the fixed Postgres advisory-lock key that
// serialises audit appends across every process sharing one audit_log
// table: the DB analogue of FileWriter's flock. Two processes that
// each read the latest entry_hash and chain from it would otherwise
// fork the chain. Arbitrary but stable; distinct from other advisory
// keys in the codebase.
const auditChainLockKey int64 = 0x617564697401 // "audit" + v1

const insertAuditRowSQL = `
	INSERT INTO audit_log (id, occurred_at, actor, event_type, payload, prev_hash, entry_hash)
	VALUES ($1, $2, $3, $4, $5, $6, $7)`

// Append implements Writer. The body mirrors FileWriter.Append
// so chain semantics match byte-for-byte: same default Actor,
// same OccurredAt clamp, same empty-payload fallback, same hash
// algorithm. The only difference is the persistence layer.
//
// When the connection is a real pool (txBeginner), each Append runs in
// a transaction guarded by pg_advisory_xact_lock and re-reads the
// latest entry_hash INSIDE the lock, so concurrent ElSereno processes
// appending to the same table serialise and never fork the chain
// (parity with FileWriter's flock). A non-pool conn (unit-test fake)
// falls back to the cached-prevHash path.
func (w *DBWriter) Append(ctx context.Context, e Entry) (Entry, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
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
	if beginner, ok := w.conn.(txBeginner); ok {
		return w.appendLocked(ctx, beginner, e)
	}
	return w.appendUnlocked(ctx, e)
}

// appendLocked runs the append inside a transaction under an exclusive
// advisory lock, re-reading the latest hash so the read-then-write is
// atomic across processes.
func (w *DBWriter) appendLocked(ctx context.Context, beginner txBeginner, e Entry) (Entry, error) {
	tx, err := beginner.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Entry{}, fmt.Errorf("audit: begin: %w", err)
	}
	// Rollback is idempotent and a no-op once Commit succeeds.
	defer func() { _ = tx.Rollback(ctx) }()

	// Blocking advisory lock, released automatically at tx end. We
	// want to wait (the critical section is a couple of fast queries),
	// so this is the plain lock, not try-lock.
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", auditChainLockKey); err != nil {
		return Entry{}, fmt.Errorf("audit: advisory lock: %w", err)
	}
	// Re-read the TRUE latest hash inside the lock, picking up any rows
	// another process committed since our cached prevHash was set.
	prev, err := readLatestHash(ctx, tx)
	if err != nil {
		return Entry{}, err
	}
	e.PrevHash = prev

	var nextID int64
	if err := tx.QueryRow(ctx, `SELECT nextval('audit_log_id_seq')`).Scan(&nextID); err != nil {
		return Entry{}, fmt.Errorf("audit: reserve id: %w", err)
	}
	e.ID = nextID
	hash, err := ComputeHash(e)
	if err != nil {
		return Entry{}, fmt.Errorf("audit: compute: %w", err)
	}
	e.EntryHash = hash

	if _, err := tx.Exec(ctx, insertAuditRowSQL,
		e.ID, e.OccurredAt, e.Actor, string(e.EventType),
		[]byte(e.Payload), e.PrevHash, e.EntryHash); err != nil {
		return Entry{}, fmt.Errorf("audit: insert: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Entry{}, fmt.Errorf("audit: commit: %w", err)
	}

	w.prevHash = hash
	w.resumed = true
	if w.observer != nil {
		w.observer(e)
	}
	return e, nil
}

// appendUnlocked is the fallback for a non-pool conn (unit tests). It
// keeps the original cached-prevHash behaviour; correct for a single
// process, which is all the fake conn simulates.
func (w *DBWriter) appendUnlocked(ctx context.Context, e Entry) (Entry, error) {
	if err := w.resumeIfNeeded(ctx); err != nil {
		return Entry{}, err
	}
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

	if _, err := w.conn.Exec(ctx, insertAuditRowSQL,
		e.ID, e.OccurredAt, e.Actor, string(e.EventType),
		[]byte(e.Payload), e.PrevHash, e.EntryHash); err != nil {
		return Entry{}, fmt.Errorf("audit: insert: %w", err)
	}

	w.prevHash = hash
	if w.observer != nil {
		w.observer(e)
	}
	return e, nil
}

// readLatestHash returns the most recent entry_hash, or GenesisPrevHash
// when the table is empty.
func readLatestHash(ctx context.Context, q queryRower) ([]byte, error) {
	var entryHash []byte
	err := q.QueryRow(ctx, `SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1`).Scan(&entryHash)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return append([]byte(nil), GenesisPrevHash...), nil
	case err != nil:
		return nil, fmt.Errorf("audit: read latest hash: %w", err)
	default:
		return entryHash, nil
	}
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
