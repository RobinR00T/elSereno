# Architecture

ElSereno is a single-binary Go application following a hexagonal
architecture. The domain (`internal/core`) depends only on the Go standard
library; adapters (db, web, protocols, inputs, outputs) depend on core.

## Directory layout

See `.context/architecture.md` for the authoritative layout and the
rationale behind each package.

## Key invariants

- Domain (`internal/core`) depends only on stdlib.
- Every I/O call carries a `context.Context` with a deadline.
- `signal.NotifyContext` is the root cancellation; second signal during
  drain exits immediately with `128 + signum`.
- Findings persistence uses `pgx.CopyFrom` batched (1000 findings or 1 s).
  Audit persistence uses sequential `INSERT` on a single goroutine (hash
  chain is non-parallelisable).
- Plugins register in `init()` via blank import in
  `cmd/elsereno/plugins.go` (or `plugins_offensive.go` for the offensive
  build).
- Parsers live in `internal/protocols/<name>/wire/` and operate on byte
  slices with length checks before slicing.
- `internal/exec.SafeCommand(ctx, CommandSpec)` is the **only** way to
  spawn subprocesses; the `--` separator is inserted deterministically
  (ADR-024).

## Module boundaries

| Package | Responsibility |
|---------|----------------|
| `internal/core` | Domain interfaces, entities, value types, shared errors. |
| `internal/bus` | Typed event channels; subscribers for findings, audit, scoring, triage, web SSE, outbox. |
| `internal/config` | Koanf loader, validator, unknown-field rejector. |
| `internal/db` | pgx pool, migrations (goose), DDL. |
| `internal/audit` | JCS hash chain (genesis / tombstone / rebase). |
| `internal/creds` | Encrypted vault (AES-GCM + Argon2id + HKDF). |
| `internal/exec` | `SafeCommand` with typed `CommandSpec`. |
| `internal/render` | `SafeBytes` sanitiser for target-controlled bytes. |
| `internal/telemetry` | zerolog, redaction hook, Prometheus, OTel. |
| `internal/web` | HTTP server, dual auth, CSRF, rate limits, health endpoints. |
| `internal/scope` | Optional `scope.yaml` + AUP flow. |
| `internal/scoring` | Multi-factor scoring engine. |
| `internal/triage` | Grouping (quick-wins, strategic). |
| `internal/doctor` | Cross-platform preflight. |
| `internal/wizard` | Interactive configuration wizard (huh). |
| `internal/protocols/<name>` | Protocol plugins (empty in F0). |
| `internal/inputs/{shodan,censys,nmapxml,list,stdin}` | Input adapters. |
| `internal/outputs/{ndjson,csv,html,cef,syslog}` | Output adapters. |
| `internal/proxy` | TCP/UDP proxy framework. |
| `internal/repl` | Generic REPL. |
| `offensive/{write,exploits,harvest,dial,sandbox}` | Offensive build modules (build tag `offensive`). |
