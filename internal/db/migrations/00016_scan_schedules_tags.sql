-- +goose Up
-- +goose StatementBegin

-- v2.4 — per-schedule labels for grouping + filtering.
-- Operators with N schedules want to tag them by environment
-- ("dev", "prod"), criticality ("critical", "best-effort"),
-- or owner ("net-team") and filter via ?tag=critical on the
-- list endpoint.
--
-- The column defaults to an empty array so existing rows
-- pre-migration come up tagless without a backfill. Validation
-- of tag shape lives Go-side (lowercase, [a-z0-9_-], max 32
-- chars, max 10 tags per schedule); the DB doesn't enforce the
-- shape — keeps the migration cheap + tag-set evolvable
-- without schema churn.
--
-- A GIN index on the column accelerates `WHERE tags && $1`
-- (array overlap) filters used by GET /schedules?tag=…

ALTER TABLE scan_schedules
    ADD COLUMN tags TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[];

CREATE INDEX idx_scan_schedules_tags
    ON scan_schedules USING GIN (tags);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_scan_schedules_tags;
ALTER TABLE scan_schedules DROP COLUMN IF EXISTS tags;
-- +goose StatementEnd
