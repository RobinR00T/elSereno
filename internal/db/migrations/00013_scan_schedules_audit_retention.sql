-- +goose Up
-- +goose StatementBegin

-- v1.89 — per-schedule audit retention override.
--
-- v1.87 introduced a global `--audit-retention-days N` flag
-- that prunes ALL schedule audit events older than the cutoff.
-- v1.89 lets operators opt specific schedules into a longer
-- (or shorter) retention window — e.g. "critical" infra
-- schedules keep audit history for 365 days even when the
-- default is 30.
--
-- NULL → use the global retention (back-compat with pre-v1.89
-- schedules + the dominant case where one global window is
-- enough). 0 → "never prune this schedule's audit" (the
-- pruner treats this as an infinite retention). >0 → "prune
-- events older than N days for this schedule".
--
-- The CHECK (>= 0) prevents negative values from sneaking in
-- via direct SQL.

ALTER TABLE scan_schedules
    ADD COLUMN audit_retention_days INTEGER NULL
        CHECK (audit_retention_days IS NULL OR audit_retention_days >= 0);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE scan_schedules DROP COLUMN IF EXISTS audit_retention_days;
-- +goose StatementEnd
