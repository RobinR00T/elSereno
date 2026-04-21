// Package repo holds the read-side data access for the HTTP
// API — `findings`, `runs`, `triage`. The write side is owned
// by `internal/audit` and `internal/bus`; this package exposes
// only SELECTs so a dashboard handler can render panels without
// touching persistence rules.
//
// Signatures take the narrow pgx Querier surface (QueryRow +
// Query) rather than a *pgxpool.Pool so unit tests can
// substitute an in-memory fake — the same pattern
// `internal/audit.DBWriter` uses.
package repo
