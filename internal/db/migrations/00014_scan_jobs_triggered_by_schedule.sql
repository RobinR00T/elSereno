-- +goose Up
-- +goose StatementBegin

-- v1.92 — per-schedule run history.
--
-- Adds a NULL-able foreign key from scan_jobs back to
-- scan_schedules so the dashboard can answer
-- "show me the last N runs of schedule X".
--
-- Semantics:
--   NULL → operator-submitted (manual) scan. Pre-v1.92 rows
--          + every dashboard "Run scan" click.
--   non-NULL → scheduler-fired scan; the value is the
--              originating schedule's ID at fire time.
--
-- ON DELETE SET NULL preserves the scan_jobs row when the
-- originating schedule is deleted — matches the v1.88 audit
-- pattern (history outlasts the schedule).
--
-- Index supports the dominant access pattern:
--   GET /api/v1/schedules/{id}/runs
--   → SELECT … WHERE triggered_by_schedule_id = ?
--          ORDER BY created_at DESC LIMIT N.

ALTER TABLE scan_jobs
    ADD COLUMN triggered_by_schedule_id TEXT NULL
        REFERENCES scan_schedules(id) ON DELETE SET NULL;

CREATE INDEX idx_scan_jobs_triggered_by_schedule
    ON scan_jobs (triggered_by_schedule_id, created_at DESC)
    WHERE triggered_by_schedule_id IS NOT NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_scan_jobs_triggered_by_schedule;
ALTER TABLE scan_jobs DROP COLUMN IF EXISTS triggered_by_schedule_id;
-- +goose StatementEnd
