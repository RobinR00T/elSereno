package handlers

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// pgQuerier is the minimum query surface PGIdempotencyCache
// needs. Both *pgxpool.Pool and *pgx.Conn satisfy it.
type pgQuerier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// PGIdempotencyCache (v2.26+) is the PG-backed IdempotencyStore.
// Schema: internal/db/migrations/00018_idempotency_keys.sql.
// Use SetDefaultIdempotencyCache(NewPGIdempotencyCache(pool))
// in cmd_serve to enable cross-process replay.
type PGIdempotencyCache struct {
	q   pgQuerier
	ttl time.Duration
}

// NewPGIdempotencyCache wraps the supplied pool with the
// default TTL of 1h (matches the in-memory cache).
func NewPGIdempotencyCache(q pgQuerier) *PGIdempotencyCache {
	return &PGIdempotencyCache{q: q, ttl: time.Hour}
}

// WithTTL returns a copy with the given TTL. Useful for
// operators that want longer/shorter replay windows.
func (c *PGIdempotencyCache) WithTTL(d time.Duration) *PGIdempotencyCache {
	out := *c
	out.ttl = d
	return &out
}

// Lookup checks the table. Returns miss/hit/conflict +
// the stored entry. TTL-expired rows are treated as miss
// (they're cleaned up by the periodic prune; the SELECT
// just filters them out via created_at).
func (c *PGIdempotencyCache) Lookup(ctx context.Context, key string, body []byte) (idempotencyLookupResult, idempotencyEntry) {
	if key == "" {
		return idempotencyMiss, idempotencyEntry{}
	}
	cutoff := time.Now().Add(-c.ttl)
	hash := hashBody(body)
	var (
		entry  idempotencyEntry
		gotKey string
	)
	err := c.q.QueryRow(ctx, `
SELECT key, body_hash, status_code, response_body, created_at
FROM idempotency_keys
WHERE key = $1 AND created_at >= $2`, key, cutoff).Scan(
		&gotKey, &entry.bodyHash, &entry.statusCode, &entry.response, &entry.storedAt,
	)
	if err != nil {
		// pgx.ErrNoRows or any IO error → treat as miss.
		// Don't bubble: idempotency is an optimisation;
		// the worst case is the inner handler re-runs.
		return idempotencyMiss, idempotencyEntry{}
	}
	if entry.bodyHash != hash {
		return idempotencyConflict, entry
	}
	return idempotencyHit, entry
}

// Store INSERTs the entry. ON CONFLICT(key) DO NOTHING so a
// concurrent retry that wins the race doesn't clobber the
// stored response (first-write-wins; subsequent calls hit
// the existing row via Lookup).
func (c *PGIdempotencyCache) Store(ctx context.Context, key string, body []byte, status int, response []byte) {
	if key == "" {
		return
	}
	hash := hashBody(body)
	_, err := c.q.Exec(ctx, `
INSERT INTO idempotency_keys (key, body_hash, status_code, response_body, created_at)
VALUES ($1, $2, $3, $4, NOW())
ON CONFLICT (key) DO NOTHING`, key, hash, status, response)
	if err != nil {
		// Best-effort: silent. Same justification as Lookup
		// — idempotency degrades gracefully.
		return
	}
}

// PruneExpired removes rows older than ttl. Operators call
// periodically (cron or a future scheduled task). Returns
// the number of deleted rows.
func (c *PGIdempotencyCache) PruneExpired(ctx context.Context) (int64, error) {
	cutoff := time.Now().Add(-c.ttl)
	tag, err := c.q.Exec(ctx, "DELETE FROM idempotency_keys WHERE created_at < $1", cutoff)
	if err != nil {
		return 0, fmt.Errorf("idempotency: prune: %w", err)
	}
	return tag.RowsAffected(), nil
}

// Compile-time check.
var _ IdempotencyStore = (*PGIdempotencyCache)(nil)
