-- +goose Up
-- +goose StatementBegin

-- v1.67 — closes the persistence gap from v1.66: the
-- per-plugin findings breakdown introduced in v1.66 lives in
-- the Job struct but had no column to land on. Without this
-- migration, db-store deployments lost the breakdown on
-- restart (memory-store kept it, but db-store is the
-- production wiring).
--
-- JSONB instead of a child table because:
--   - The map is bounded (≤30 plugins per scan in the worst
--     case, even with empty Plugins list).
--   - It's only read in aggregate alongside the rest of the
--     row — never queried by plugin name.
--   - JSONB lets us round-trip Go map[string]int via the
--     pgx driver without an extra join.
--
-- Default '{}'::jsonb so existing rows from migration 00005
-- get a non-NULL default that the Go side decodes as an empty
-- map. (NULL would force a *map indirection on the scan.)

ALTER TABLE scan_jobs
    ADD COLUMN findings_by_plugin JSONB NOT NULL DEFAULT '{}'::jsonb;

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE scan_jobs DROP COLUMN IF EXISTS findings_by_plugin;
-- +goose StatementEnd
