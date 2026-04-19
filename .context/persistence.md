---
phase: any
status: canonical
last-updated: 2026-04-19
token-budget: 2000
---

# Persistence

Primary store: Postgres 16. Portable variant: SQLite via `-tags sqlite`
(CGO, native runner arch only — ADR-012, PITF-006).

## Core tables (migration 00001)

- `schema_info(contract_name, version, since)` — e.g. `ndjson=v1`, `api=v1`.
- `web_state(key, token_generation, updated_at)` — persistent token
  generation; bumped with advisory lock on `token rotate` (ADR-014, PITF-001,
  PITF-026). Middleware cache TTL `web.token_generation_cache_ttl` (default
  5 s; PITF-034).
- `runs(id, started_at, finished_at, status, scope_hash, operator)`.
- `targets(id, address inet, port, asn, country, first_seen, last_seen)` —
  `UNIQUE(address, port)`.
- `findings(id, run_id, target_id, protocol, severity, score, finding_hash,
  created_at, factors jsonb)` — indexed by `(score, severity)`, `run_id`,
  `protocol`, `finding_hash`.
- `evidence(id, finding_id → findings.id ON DELETE CASCADE, payload,
  payload_truncated, original_size, original_sha256, captured_at)` —
  `original_sha256` populated **only** when `payload_truncated = TRUE`.
- `sessions(id, run_id, target_id, protocol, started_at, ended_at,
  transcript jsonb)`.
- `audit_log(id bigserial, occurred_at, actor, event_type CHECK enum,
  payload jsonb, payload_tombstoned, prev_hash, entry_hash UNIQUE)` —
  source of truth for the enum (PITF-030).
- `audit_purge_markers(id, performed_at, purged_before, purged_rows,
  audit_entry_id → audit_log.id ON DELETE RESTRICT)` — FK restricted
  (PITF-033); `audit compact` excludes entries with `event_type IN
  ('genesis','chain_rebase','purge_event')` (ADR-013, ADR-025).
- `outbox(id, created_at, kind, payload, attempts, next_try_at,
  delivered_at)` — partial index `next_try_at WHERE delivered_at IS NULL`.
- `outbox_dead(id, moved_at, kind, payload, attempts, last_error)` —
  indexed by `moved_at` (PITF-027).
- `tags(target_id → targets.id ON DELETE CASCADE, key, value)`.
- `scope_history(id, applied_at, scope_yaml, scope_hash)`.
- `creds_vault(name, ciphertext, nonce, salt, created_at, rotated_at)`.

## Retention

- `retention.findings_days`
- `retention.evidence_days` — **keep-if-referenced**: do not delete an
  evidence row while any finding still references it.
- `retention.runs_days`

## Migrations

`goose` embedded via `embed.FS`. `elsereno db migrate up/down/status` and
`elsereno db verify` (structural and row-count invariants).

## TLS

`database.tls_required` ∈ {`auto`, `always`, `disable`} (ADR-021). `auto`
requires TLS unless the host is loopback (`127.0.0.1`, `::1`).
`disable` is rejected at runtime for non-loopback hosts.

## Timestamps

RFC 3339 with up to 6 fractional digits (microseconds; Postgres
`TIMESTAMPTZ`). Not "Nano" — ADR-020, PITF-024.
