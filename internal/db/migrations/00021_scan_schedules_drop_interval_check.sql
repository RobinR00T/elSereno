-- +goose Up
-- +goose StatementBegin

-- 00008 meant to drop the v1.71 CHECK (interval_seconds BETWEEN 60 AND
-- 604800) by matching 'BETWEEN' in pg_get_constraintdef, but PostgreSQL
-- stores BETWEEN rewritten as (interval_seconds >= 60) AND
-- (interval_seconds <= 604800), so nothing matched: the old CHECK stayed
-- next to scan_schedules_cadence_xor and rejected every cron schedule,
-- which stores interval_seconds = 0 (PITF-086). Drop every CHECK on the
-- table that bounds interval_seconds at 604800 without mentioning
-- cron_expr: the inline 00007 one, or scan_schedules_interval_check if
-- 00008 was rolled back. The cadence XOR, which mentions both, stays, and
-- so would a CHECK an operator added by hand, unless it also bounds at
-- 604800. Idempotent: a second run,
-- or a database where 00008 did drop it (none known), matches nothing.
DO $$
DECLARE
    c TEXT;
BEGIN
    FOR c IN
        SELECT conname
        FROM pg_constraint
        WHERE conrelid = 'scan_schedules'::regclass
          AND contype = 'c'
          AND pg_get_constraintdef(oid) ILIKE '%interval_seconds%'
          AND pg_get_constraintdef(oid) LIKE '%604800%'
          AND pg_get_constraintdef(oid) NOT ILIKE '%cron_expr%'
    LOOP
        EXECUTE 'ALTER TABLE scan_schedules DROP CONSTRAINT ' || quote_ident(c);
    END LOOP;
END $$;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

-- Nothing to restore: the dropped CHECK contradicts
-- scan_schedules_cadence_xor (it rejects interval_seconds = 0, which a
-- cron schedule needs), so re-adding it would break every cron row.
SELECT 1;

-- +goose StatementEnd
