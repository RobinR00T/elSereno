-- +goose Up
-- +goose StatementBegin

-- v2.1 — extend scan_schedule_audit CHECK enum with the
-- `cloned_from` event type. v1.93 added the clone endpoint
-- but no audit row was written, so compliance reviews
-- couldn't trace clone provenance. v2.1 closes that gap:
-- after a successful clone the handler writes one audit row
-- with schedule_id = clone.id, payload_before = source
-- snapshot, payload_after = clone snapshot.
--
-- Migration 00012 set the canonical pattern (DROP + ADD the
-- CHECK with the wider set). PITF-030 — SQL DDL is source of
-- truth, mirrored Go-side by ValidScheduleAuditEventTypes.

ALTER TABLE scan_schedule_audit
    DROP CONSTRAINT scan_schedule_audit_event_type_check;

ALTER TABLE scan_schedule_audit
    ADD CONSTRAINT scan_schedule_audit_event_type_check
    CHECK (event_type IN (
        'force_overwrite',
        'delete',
        'set_enabled_true',
        'set_enabled_false',
        'cloned_from'
    ));

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin

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
