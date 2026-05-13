-- +goose Up
-- +goose StatementBegin

-- v2.10 — fast clone-provenance via dedicated FK column.
--
-- v2.1 introduced the `cloned_from` audit event but the only
-- way to answer "show me everything cloned FROM X" was to
-- grep payload_before.id off the audit log — slow + N rows
-- to scan per operator query. v2.10 adds a direct
-- source_schedule_id column on scan_schedules so the
-- provenance query becomes:
--
--   SELECT … WHERE source_schedule_id = $1;
--
-- NULL = "not a clone of anything" (the dominant case;
-- every operator-created schedule has NULL here).
-- non-NULL = "this schedule was cloned from the referenced
--           one".
--
-- ON DELETE SET NULL preserves the clone row when the
-- source is deleted (matches v1.88 + v1.92 patterns —
-- history outlasts the source).
--
-- A partial index on the non-NULL set keeps the v2.5 list
-- queries fast even when the table is large; clones are a
-- minority of rows in typical fleets.

ALTER TABLE scan_schedules
    ADD COLUMN source_schedule_id TEXT NULL
        REFERENCES scan_schedules(id) ON DELETE SET NULL;

CREATE INDEX idx_scan_schedules_source
    ON scan_schedules (source_schedule_id)
    WHERE source_schedule_id IS NOT NULL;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_scan_schedules_source;
ALTER TABLE scan_schedules DROP COLUMN IF EXISTS source_schedule_id;
-- +goose StatementEnd
