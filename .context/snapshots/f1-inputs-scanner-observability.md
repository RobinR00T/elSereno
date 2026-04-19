---
phase: F1
date: 2026-04-19
token-budget: 1000
---

# Phase F1 snapshot — Inputs, scanner, scoring, triage, observability

Delivered across two chunks on 2026-04-19. `make ci` green after each
chunk on the operator's machine.

## Shipped

### CLI and config
- cobra rewires `cmd/elsereno` with a real verb tree.
- Working verbs: `version`, `doctor`, `legal`, `plugins (list)`,
  `config (show|lint)` with `--format yaml|json|table`, `scoring
  (show|example)`.
- Typed `EX_TEMPFAIL` stubs for the rest, each naming its phase.
- Koanf loader with struct-tag walker rejecting unknown YAML keys via
  `ErrUnknownConfigField`; validator-driven enum check for
  `database.tls_required` (ADR-021).

### Observability
- Zerolog logger with RFC 3339 μs timestamps.
- `Redact(key, value)` with specific-pattern match + Shannon entropy
  heuristic (>4.5 bits/byte) with UUID v1–v5 exemption (PITF-004).
- Prometheus metrics: `elsereno_findings_total{protocol,severity,asn,
  country}`, `elsereno_scan_duration_seconds`, `elsereno_persistence_
  lag_seconds`, `elsereno_audit_entries_total`, `elsereno_outbox_
  inflight`. Label sanitiser pins protocol/severity to a fixed set,
  enforces numeric-only ASN and ISO 3166-1 alpha-2 country; anything
  else collapses to `"unknown"` to cap cardinality.

### Persistence adapters
- `internal/db`: pgxpool with ADR-021 TLS policy enforcement; goose
  migration runner wired via `pgx/v5/stdlib.OpenDBFromPool` so
  `MigrateUp`, `MigrateDown`, `MigrateStatus`, `Verify` work against a
  live Postgres.
- Migrations embedded via `embed.FS` (copy of migrations/00001).

### Inputs
- `internal/inputs/list`: newline-separated IPv4/IPv6 with optional
  port; bracketed IPv6; blank / `#` lines skipped; limit enforcement.
- `internal/inputs/stdin`: thin wrapper over list for `elsereno scan
  --input stdin`.
- `internal/inputs/nmapxml`: streaming xml.Decoder for `nmap -oX`
  files; only open ports; IPv4/IPv6 address types.
- `internal/inputs/shodan`: minimal Shodan REST client (search API)
  with `golang.org/x/time/rate` limiter. Credentials load from env or
  (chunk 3) vault; argv transport remains banned (PITF-016).

### Outputs
- `internal/outputs/ndjson` (schema `ndjson:v1`): line-per-finding
  JSON with stable field names.
- `internal/outputs/csv` (schema `csv:v1`): stable column order, lazy
  header.
- `internal/outputs/html` (schema `html:v1`): self-contained report
  with totals-by-severity card block and a table of findings. Uses
  `html/template` (ADR-007).

### Scoring + triage
- `internal/scoring`: six-factor engine with embedded
  `defaults/weights.yaml` (ADR-006). `Validate` enforces sum=1.0±1e-9
  and per-factor bounds [0,1]; `Score` clamps to [0,100] and derives
  Severity; `Factors()` returns a stable ordered list.
- `internal/triage`: `Group(f)` buckets into `quick_win` (critical/high
  with auth_state ≤ 10), `strategic` (critical with impact_class ≥
  60), or `routine`. `BucketFindings` aggregates and sorts each
  bucket by score descending.

### Scanner core
- `internal/scanner`: resolve (A + AAAA + IDN via `x/net/idna`),
  Dedupe (tuple key with IPv4-mapped normalisation), and `Run` with
  per-host + global concurrency semaphores (`x/sync/semaphore`),
  optional token-bucket rate limiting (`x/time/rate`), exponential
  backoff + jitter retries on `core.ErrTimeout` /
  `context.DeadlineExceeded`.

### Vault (unlock-once)
- `internal/creds.Vault`: AES-GCM + Argon2id (`time=3, memory=64 MiB,
  threads=4`). Master key in `memguard.LockedBuffer`, zeroised on
  `Lock()` or process exit. `Derive(info, out)` implements
  HKDF-SHA256 — the CSRF key (ADR-017) and future derivations hang off
  this. `Init` refuses silent re-initialisation (PITF-021). `Unlock`
  verifies a GCM-sealed sentinel so a bad passphrase fails clean.
  `Store/Retrieve/Rotate/Purge/Metadata/List` plus a
  `SnapshotForTesting` escape hatch for round-trip tests.

## Non-trivial decisions made

- PITF-011 dep verification: pgx, koanf, zerolog, cobra, validator,
  goose, memguard, prometheus, x/time, x/net/idna all actively
  maintained (checked in session). Memguard's macOS `mlock` fallback
  is documented but remains a best-effort on that platform.
- Scanner jitter uses `math/rand/v2` with an inline `#nosec G404`; it
  is deliberately not cryptographic.
- `internal/db/migrations.go` bridges pgx→`*sql.DB` via
  `stdlib.OpenDBFromPool`, opening the pooled connection lifetime to
  goose while keeping our public API pgxpool-based.
- HTML package carries a per-package misspell exemption (`.golangci.yml`)
  because CSS property names (`color`, `center`) are invariant across
  locales and fight the UK dictionary.

## New pitfalls captured

None beyond PITF-001..036. No new anti-patterns surfaced.

## Debt accepted

- **No live-Postgres integration test** yet. `internal/db` compiles
  and uses the real pgx stdlib bridge, but exercising migrations
  end-to-end requires docker-compose up and sits under
  `//go:build integration`. That lands alongside the F1 chunk 3 chaos
  helpers.
- **Censys HTTP client** not landed — Shodan demonstrates the pattern
  and Censys uses HTTP Basic, which is a smaller diff.
- **Outbox with dead letter**, **retention keep-if-referenced**, and
  **progress bars with NO_COLOR** deferred to F1 chunk 3.
- **Web server** (ADR-014) not started. Placeholders still
  `EX_TEMPFAIL`. Vault is in place, so CSRF-key derivation is
  unblocked whenever we wire the server.
- **CLI verbs** `db migrate/status/verify/backup/reset`, `vault
  init/unlock/lock/status`, `creds store/list/show/rotate/purge`,
  `token rotate/show`, `audit verify/purge/compact` are still in
  `cmd_stubs.go`. The adapters they need now exist; wiring is
  straightforward plumbing deferred to keep chunk-2 reviewable.

## What moves to next phase (F1 chunk 3)

- Wire the remaining CLI verbs to their adapters (db/vault/creds/
  audit/token).
- Censys client.
- Outbox worker with max_attempts + dead-letter.
- Retention enforcement (keep-if-referenced).
- Progress bars with ETA + NO_COLOR.
- Web server scaffold (http.Server with full timeouts) so F1 can
  close.
- Integration test suite (`//go:build integration`) + docker-compose
  simulators.
