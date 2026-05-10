-- +goose Up
-- +goose StatementBegin

-- v1.84 — audit log for the schedule edit path.
-- Currently records force_overwrite events (operator
-- submitted a PUT without If-Match, overriding the v1.78
-- optimistic-locking precondition). Future cycles may add
-- delete / set_enabled / etc.
--
-- The CHECK constraint on event_type is the source of truth
-- mirrored Go-side by ValidScheduleAuditEventTypes — keeping
-- both in sync is operator hygiene (per PITF-030).

CREATE TABLE scan_schedule_audit (
    id              TEXT NOT NULL PRIMARY KEY,
    schedule_id     TEXT NOT NULL REFERENCES scan_schedules(id) ON DELETE CASCADE,
    event_type      TEXT NOT NULL
                       CHECK (event_type IN ('force_overwrite')),
    operator        TEXT NOT NULL,
    occurred_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    payload_before  JSONB NOT NULL,
    payload_after   JSONB NOT NULL
);

-- DESC index supports the dominant access pattern: list-
-- newest-first for a given schedule.
CREATE INDEX scan_schedule_audit_schedule_at_idx
    ON scan_schedule_audit (schedule_id, occurred_at DESC);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS scan_schedule_audit;
-- +goose StatementEnd
