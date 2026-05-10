-- +goose Up
-- +goose StatementBegin

-- v1.75 — adds the timezone column for cron-based schedules.
-- Empty (default '') means UTC, matching v1.73/v1.74 cron
-- evaluation behaviour. Operators set IANA names like
-- 'America/New_York' or 'Europe/Madrid' so cron expressions
-- evaluate against local wall-clock time.
--
-- Pre-v1.75 cron schedules: timezone defaults to '' which
-- decodes Go-side as time.UTC — same behaviour as before.
-- No data migration needed.
--
-- Validation lives in the Go layer (time.LoadLocation): we
-- intentionally don't add a SQL CHECK constraint because
-- PostgreSQL's view of valid IANA names depends on the
-- server's tzdata bundle, which isn't a stable contract.

ALTER TABLE scan_schedules
    ADD COLUMN timezone TEXT NOT NULL DEFAULT '';

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE scan_schedules DROP COLUMN IF EXISTS timezone;
-- +goose StatementEnd
