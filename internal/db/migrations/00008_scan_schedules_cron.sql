-- +goose Up
-- +goose StatementBegin

-- v1.73 — adds the cron_expr column for cron-based scan
-- schedules (alternative to v1.70/71's interval_seconds).
-- Exactly one of interval_seconds and cron_expr must be set
-- per row, enforced via a replacement CHECK constraint that
-- supersedes the v1.71 [60, 604800] interval bound.
--
-- Pre-v1.73 rows: interval_seconds is in [60, 604800] and
-- cron_expr defaults to '' — both satisfy the new CHECK.
-- No data migration needed.

ALTER TABLE scan_schedules
    ADD COLUMN cron_expr TEXT NOT NULL DEFAULT '';

-- The v1.71 CHECK (interval_seconds BETWEEN 60 AND 604800) is
-- baked into the table definition; PostgreSQL doesn't expose
-- a stable name for it across versions. Drop by inspection
-- via the constraint catalogue — the only CHECK constraint on
-- the table at this point is the interval bound. The DROP IS
-- guarded with IF EXISTS in the synthetic name fallback.
DO $$
DECLARE
    constraint_name TEXT;
BEGIN
    SELECT conname INTO constraint_name
    FROM pg_constraint
    WHERE conrelid = 'scan_schedules'::regclass
      AND contype = 'c'
      AND pg_get_constraintdef(oid) ILIKE '%interval_seconds%BETWEEN%';
    IF constraint_name IS NOT NULL THEN
        EXECUTE 'ALTER TABLE scan_schedules DROP CONSTRAINT ' || quote_ident(constraint_name);
    END IF;
END $$;

-- New combined CHECK: exactly one of interval_seconds (in
-- [60, 604800]) or cron_expr (non-empty) is set per row.
ALTER TABLE scan_schedules
    ADD CONSTRAINT scan_schedules_cadence_xor CHECK (
        (interval_seconds = 0 AND cron_expr <> '')
        OR (interval_seconds BETWEEN 60 AND 604800 AND cron_expr = '')
    );

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE scan_schedules DROP CONSTRAINT IF EXISTS scan_schedules_cadence_xor;
ALTER TABLE scan_schedules ADD CONSTRAINT scan_schedules_interval_check
    CHECK (interval_seconds BETWEEN 60 AND 604800);
ALTER TABLE scan_schedules DROP COLUMN IF EXISTS cron_expr;
-- +goose StatementEnd
