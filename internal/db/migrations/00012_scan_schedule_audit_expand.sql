-- +goose Up
-- +goose StatementBegin

-- v1.88 — expand scan_schedule_audit:
--   1. Add new event_type values (delete, set_enabled_true,
--      set_enabled_false). The Go enum mirrors this CHECK
--      via ValidScheduleAuditEventTypes (PITF-030 source of
--      truth — SQL DDL).
--   2. Relax the schedule_id FK to ON DELETE SET NULL.
--      v1.84's CASCADE meant deleting a schedule wiped its
--      audit history; v1.88 keeps the history with
--      schedule_id = NULL so a downstream operator can still
--      see what changed before the delete.
--   3. Drop NOT NULL on schedule_id (required for SET NULL
--      to work).

ALTER TABLE scan_schedule_audit
    ALTER COLUMN schedule_id DROP NOT NULL;

ALTER TABLE scan_schedule_audit
    DROP CONSTRAINT scan_schedule_audit_schedule_id_fkey;

ALTER TABLE scan_schedule_audit
    ADD CONSTRAINT scan_schedule_audit_schedule_id_fkey
    FOREIGN KEY (schedule_id) REFERENCES scan_schedules(id) ON DELETE SET NULL;

-- CHECK constraint name is the postgres-default
-- scan_schedule_audit_event_type_check, generated for the
-- inline CHECK in 00011. Drop + recreate with the wider
-- enumeration.
ALTER TABLE scan_schedule_audit
    DROP CONSTRAINT scan_schedule_audit_event_type_check;

ALTER TABLE scan_schedule_audit
    ADD CONSTRAINT scan_schedule_audit_event_type_check
    CHECK (event_type IN (
        'force_overwrite',
        'delete',
        'set_enabled_true',
        'set_enabled_false'
    ));

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

ALTER TABLE scan_schedule_audit
    DROP CONSTRAINT scan_schedule_audit_event_type_check;

ALTER TABLE scan_schedule_audit
    ADD CONSTRAINT scan_schedule_audit_event_type_check
    CHECK (event_type IN ('force_overwrite'));

ALTER TABLE scan_schedule_audit
    DROP CONSTRAINT scan_schedule_audit_schedule_id_fkey;

ALTER TABLE scan_schedule_audit
    ADD CONSTRAINT scan_schedule_audit_schedule_id_fkey
    FOREIGN KEY (schedule_id) REFERENCES scan_schedules(id) ON DELETE CASCADE;

ALTER TABLE scan_schedule_audit
    ALTER COLUMN schedule_id SET NOT NULL;

-- +goose StatementEnd
