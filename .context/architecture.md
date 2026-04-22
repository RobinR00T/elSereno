---
phase: any
status: canonical
last-updated: 2026-04-19
token-budget: 2000
---

# Architecture

## Style
Hexagonal. `internal/core` depends only on stdlib. Adapters
(`internal/db`, `internal/web`, `internal/protocols/*`,
`internal/inputs/*`, `internal/outputs/*`) depend on core.

## Async
`context.Context` propagated through every call. Every I/O has a deadline.

## Signal handling
`signal.NotifyContext(ctx, SIGINT, SIGTERM)`.
- First signal → cancel root ctx → drain up to `shutdown.drain_timeout`
  (10s default) → flush → `exit(128+signum)` (SIGINT=130, SIGTERM=143).
- Second signal during drain → immediate exit with the same code.

## Event bus (`internal/bus`)
Typed channels. Subscribers:
- `findings-persistence`: buffered goroutine (1000 findings or 1 s) →
  `pgx.CopyFrom`.
- `audit-persistence`: **single-threaded** sequential INSERT (hash chain
  is not parallelisable).
- `scoring`, `triage`, `web-sse`, `outbox`.

## Plugins (`internal/protocols/<name>/`)
Implement `core.Protocol`:
- `Probe(ctx, target) (*Finding, error)`
- `REPL(ctx, session) error`
- `ProxyHandler() core.ProxyHandler`
- `Metadata() PluginMetadata`

Registered in `init()` via blank imports in `cmd/elsereno/plugins.go`
(default) or `plugins_offensive.go` (`-tags offensive`).

## Build tags
- `offensive`: writes, exploits, harvest, dial.
- `sandbox_integration`: kernel-level seccomp-bpf tests (Linux).
- Default: read-only, Postgres-only, pure Go (no CGO).

## IPv6 first-class
Loopback = `127.0.0.1/8 ∪ ::1/128`. Hostnames resolved to all A+AAAA and
deduped by `(addr, port)` before scanning. IDN via `x/net/idna.Lookup.ToASCII`.

## Directory layout

| Path | Responsibility |
|------|----------------|
| `cmd/elsereno/` | `main.go`, `plugins.go`, `plugins_offensive.go`, `doc.go`. |
| `internal/core/` | Domain interfaces, entities, value types, shared errors. |
| `internal/bus/` | Typed events + subscribers. |
| `internal/config/` | Koanf + validator + strict unknown-field rejector. |
| `internal/wizard/` | `huh` wizard. |
| `internal/doctor/` | Cross-platform preflight. |
| `internal/exec/` | `SafeCommand` + `CommandSpec` + path allowlist + `--` enforcement. |
| `internal/inputs/{shodan,censys,nmapxml,list,stdin}/` | Input adapters. |
| `internal/scanner/` | Resolve + dedupe + scan. |
| `internal/scope/` | `scope.yaml` + AUP flow. |
| `internal/protocols/` | Plugins. |
| `internal/proxy/` | TCP/UDP framework. |
| `internal/repl/` | Generic REPL. |
| `internal/scoring/` | Engine + YAMLs. |
| `internal/triage/` | Grouping. |
| `internal/outputs/{ndjson,csv,html,cef,syslog}/` | Output adapters. |
| `internal/render/` | `SafeBytes`. |
| `internal/creds/` | Vault AES-GCM + Argon2id + HKDF + unlock-once. |
| `internal/audit/` | Genesis + tombstones + rebase + JCS + `ErrChainBroken`. |
| `internal/db/` | pgx pool + migrations + DDL. |
| `internal/telemetry/` | Prometheus + OTel + redaction hook + `SafeField`. |
| `internal/web/` | HTTP server, handlers, middleware, templates, static. |
| `offensive/{write,exploits,harvest,dial,sandbox}/` | Offensive modules. |
