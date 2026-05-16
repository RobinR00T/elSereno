-- +goose Up
-- +goose StatementBegin

-- v2.26 — multi-process Idempotency-Key cache.
--
-- v2.18 + v2.25 used a per-process in-memory map; a load-
-- balanced multi-process serve loses replay semantics when
-- the retry lands on a different worker. This table backs
-- the cache across processes.
--
-- Storage shape mirrors the v2.18 idempotencyEntry struct:
--   key            → unique header value (PK).
--   body_hash      → SHA-256 hex of the request body (for
--                    conflict detection).
--   status_code    → cached response status.
--   response_body  → cached response bytes (JSON).
--   created_at     → for TTL eviction.
--
-- Operators run a periodic prune (cron / future task) to
-- evict expired keys; the table is bounded only by retention.

CREATE TABLE idempotency_keys (
    key            TEXT NOT NULL PRIMARY KEY,
    body_hash      TEXT NOT NULL,
    status_code    INTEGER NOT NULL,
    response_body  BYTEA NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index supports the periodic TTL prune query
-- (DELETE WHERE created_at < cutoff).
CREATE INDEX idx_idempotency_keys_created_at
    ON idempotency_keys (created_at);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS idempotency_keys;
-- +goose StatementEnd
