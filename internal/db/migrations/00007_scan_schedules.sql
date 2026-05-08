-- +goose Up
-- +goose StatementBegin

-- v1.71 — closes the v1.70 honest-scope gap: scan schedules
-- now persist across `serve` restarts. The MemoryScheduleStore
-- stays available for tests + dev; production wiring switches
-- to DBScheduleStore when --scan-store=db.
--
-- Schema:
--
--   - id is the 16-hex schedule identifier (mirrors scan_jobs).
--   - template_* columns flatten the Go SubmitRequest. Choosing
--     three columns over a JSONB blob because the Submit shape
--     is small + stable, and we'd want indexable plugin-list
--     queries in the future.
--   - interval_seconds CHECK enforces the same [60, 604800]
--     range as the Go MemoryScheduleStore, defense in depth
--     against an out-of-band INSERT (psql / data import).
--   - last_fired_at NULL means never-fired (Scheduler reads
--     NULL → IsDue=true on the next tick).

CREATE TABLE scan_schedules (
    id                    TEXT        PRIMARY KEY,
    name                  TEXT        NOT NULL,
    template_input        TEXT        NOT NULL,
    template_plugins      TEXT[]      NOT NULL DEFAULT ARRAY[]::TEXT[],
    template_default_port INTEGER     NOT NULL DEFAULT 0,
    interval_seconds      INTEGER     NOT NULL,
    enabled               BOOLEAN     NOT NULL DEFAULT TRUE,
    operator              TEXT        NOT NULL DEFAULT '',
    created_at            TIMESTAMPTZ NOT NULL,
    last_fired_at         TIMESTAMPTZ,
    CHECK (interval_seconds BETWEEN 60 AND 604800),
    CHECK (template_input <> '')
);

-- Indices supporting the two hot paths:
--   1. List() ORDER BY name ASC — dashboard read.
--   2. Scheduler tick: WHERE enabled = TRUE — most schedules
--      are enabled, but disabled ones are skipped.
CREATE INDEX idx_scan_schedules_name    ON scan_schedules(name);
CREATE INDEX idx_scan_schedules_enabled ON scan_schedules(enabled) WHERE enabled = TRUE;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_scan_schedules_enabled;
DROP INDEX IF EXISTS idx_scan_schedules_name;
DROP TABLE IF EXISTS scan_schedules;
-- +goose StatementEnd
