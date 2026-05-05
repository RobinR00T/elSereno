-- +goose Up
-- +goose StatementBegin

-- v1.60 — scan-job orchestration persistent storage.
-- Backs internal/scanorch.Store via the new
-- internal/scanorch/store_pg.go implementation. The shape
-- mirrors scanorch.Job + the SubmitRequest fields. State is
-- a CHECK-constrained enum so any out-of-band INSERT (e.g.
-- via psql) can't introduce a bogus state and corrupt the
-- worker's state-machine assumptions.

CREATE TABLE scan_jobs (
    id              TEXT        PRIMARY KEY,
    state           TEXT        NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL,
    started_at      TIMESTAMPTZ,
    finished_at     TIMESTAMPTZ,
    input           TEXT        NOT NULL,
    plugins         TEXT[]      NOT NULL DEFAULT ARRAY[]::TEXT[],
    default_port    INTEGER     NOT NULL DEFAULT 0,
    targets_seen    BIGINT      NOT NULL DEFAULT 0,
    targets_scanned BIGINT      NOT NULL DEFAULT 0,
    findings_count  BIGINT      NOT NULL DEFAULT 0,
    error_msg       TEXT        NOT NULL DEFAULT '',
    operator        TEXT        NOT NULL DEFAULT '',
    CHECK (state IN ('queued','running','completed','failed','cancelled'))
);

-- Indices supporting the dashboard's two hot paths:
--   1. List() ORDER BY created_at DESC LIMIT N
--   2. Worker drain: WHERE state = 'queued'
CREATE INDEX idx_scan_jobs_created_at ON scan_jobs(created_at DESC);
CREATE INDEX idx_scan_jobs_state      ON scan_jobs(state);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_scan_jobs_state;
DROP INDEX IF EXISTS idx_scan_jobs_created_at;
DROP TABLE IF EXISTS scan_jobs;
-- +goose StatementEnd
