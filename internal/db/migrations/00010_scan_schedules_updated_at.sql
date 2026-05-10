-- +goose Up
-- +goose StatementBegin

-- v1.78 — adds the updated_at column for optimistic-locking
-- on schedule edits. Set on Create (= created_at) and bumped
-- by every Update; the If-Match HTTP header on PUT carries
-- the operator's last-known value, and a mismatch yields 412.
--
-- Pre-v1.78 schedules backfill from created_at — they've
-- never been edited, so updated_at == created_at is the
-- correct logical value.

ALTER TABLE scan_schedules
    ADD COLUMN updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

UPDATE scan_schedules
   SET updated_at = created_at;

-- Drop the default once the backfill has run; new rows write
-- updated_at explicitly via the v1.78 INSERT.
ALTER TABLE scan_schedules
    ALTER COLUMN updated_at DROP DEFAULT;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE scan_schedules DROP COLUMN IF EXISTS updated_at;
-- +goose StatementEnd
