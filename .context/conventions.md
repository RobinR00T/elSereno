---
phase: any
status: canonical
last-updated: 2026-04-19
token-budget: 2500
---

# Conventions

## Go style
- gofmt + goimports strict.
- golangci-lint profile in `.golangci.yml` is authority.
- Package names singular lowercase no underscores.
- Errors wrapped with `%w`. Sentinels live in emitting package: `ErrChainBroken` in `internal/audit/`, `ErrUnknownConfigField` in `internal/config/`; `internal/core/errors.go` only for shared domain errors.
- Contexts always first arg, never in structs (containedctx).
- No panics outside `main` and tests. Goroutines wrap with `defer recover`.
- No `init()` side effects except plugin registration.
- Every package has `doc.go`.
- Typed values (`core.Port`, `core.Severity`, `core.Confidence`).
- Type assertions checked (forcetypeassert).
- Subprocess only via `internal/exec.SafeCommand(ctx, CommandSpec)` — deterministic `--` separator.
- Signal handling via `signal.NotifyContext`. Exit 128+signum (SIGINT=130, SIGTERM=143).

## Testing
- Table-driven with `t.Run`.
- Coverage per package: protocols 90%, core 85%, else 80%.
- Fuzz mandatory for binary parsers (`FuzzXxx`).
- Integration `//go:build integration` (Linux-only unless justified).
- E2E `//go:build e2e`.
- testify + go-cmp.
- No network in unit tests.
- Golden files `testdata/` with `-update` flag.
- `funlen` exempt in `_test.go` (max 120/80).
- Darwin skips Linux-only via `t.Skip` based on `runtime.GOOS`.

## Commits and branches
- Conventional Commits.
- One logical change per commit.
- Default branch `main`.
- DCO sign-off `-s`.

## Security rules (hard)
- No direct `os/exec.Command`; use `internal/exec.SafeCommand` with `CommandSpec`.
- No `yaml.Unmarshal` without strict; Koanf config rejects unknown fields post-load.
- No `encoding/gob` over untrusted input.
- Every I/O has context with deadline.
- Every parser has length checks before slicing.
- Every target-controlled string via `telemetry.SafeField` before logging.
- Every target-controlled bytes via `internal/render.SafeBytes` before rendering.
- Secrets in `memguard.LockedBuffer`, zeroized; doctor verifies mlock.
- No credentials in logs. Redaction hook with specific patterns (api_key/secret_key/private_key/access_key/session_key/encryption_key/auth_token/refresh_token/bearer_token/password/passphrase/secret/authorization/cookie) + entropy heuristic excluding UUID format.
- TLS verification always on. `--insecure-*` per call site only.
- Postgres TLS required when not loopback; prefer `.pgpass`/`PGSERVICEFILE` over DSN password.
- Audit: tombstone preserves chain; compact inserts rebase marker and **skips** entries `event_type IN ('genesis','chain_rebase','purge_event')`. Canonical JCS fields: id/occurred_at/actor/event_type/payload/prev_hash. Genesis `prev_hash=0x00..00`. Actor `'system'` for non-attributable.
- AT dialing / SMS requires `-tags offensive` + `--dial-allowed`. Numbers ≤3 digits blocked hard. Proxy read-only blocks: ATD*, ATA, AT+CMGS, AT+CMGW, AT+CMSS, AT+CMGD, AT+CFUN, AT+CPWROFF, +++.
- Offensive subprocess with seccomp-bpf on Linux (lib decision deferred to F5).
- `crypto/rand` only.
- Web tokens 32B crypto/rand base64url.
- `token_generation` persisted in `web_state`; bumped with advisory lock on rotate; middleware caches generation TTL 5s.
- CSRF key HKDF from vault; `serve` requires vault unlocked.
- Vault unlock-once memguard; zeroized on SIGINT/SIGTERM or `vault lock`.
- `http.Server` with full timeouts (5s/30s/30s/120s/16KiB).
- `config show` redacts secrets; `--unsafe` shows.
- Cookie Secure=true with TLS; false on HTTP loopback with rationale comment.
- Rate limit per-IP AND per-token; loopback exempt from per-IP.
- **Secrets discipline** (ADR-026, PITF-016, PITF-032):
  - Never via argv.
  - Never via herestring (`<<< "KEY"`).
  - Env vars with secrets leak via `/proc/<pid>/environ` and `ps e`; warning on startup if TTY present + secret env set; prefer file 0600 for persistent use; env acceptable for CI/cron with documented rationale.
- Never reference prior versions of documents; expand inline (PITF-007).
- `make ci` must be superset of CI bitrot-catching jobs (PITF-031).

## File size
- Source files max 500 lines.
- Context files max 250 lines.
- Functions max 60 lines / 40 statements; tests 120/80.
- Cyclomatic max 15.

## Documentation
- Every exported symbol has godoc.
- Every package `doc.go`.
- Every protocol `.context/protocols/<name>.md`.
- Every design decision has an ADR.
- Every anti-pattern discovered → `.context/pitfalls.md`.

## Concurrency
- `errgroup`, `semaphore`, `x/time/rate`.
- No shared mutable state without lock justification in code.
- Audit persistence single-threaded.
- Findings persistence via `pgx.CopyFrom` batched.

## Observability
- Timestamps RFC3339 up to 6 fractional digits.
- Logs stderr; data stdout.
- Log level default `info`.
- Prometheus labels low-cardinality (`protocol`, `severity`, `asn`, `country`); never `ip`. Label sanitizer validates against expected set.
- Request IDs propagated; OTel-compatible.

## CLI UX
- Globals: `--format`, `--dry-run`, `--quiet`, `--verbose`, `--config`.
- Respect `NO_COLOR`, `TERM=dumb`.
- Exit codes per sysexits(3) + 128+signum for signals.
- Errors include resolution hints.

## Web UX
- `html/template` only.
- CSP nonces per request.
- API `/api/v1/*`: Bearer, no CSRF.
- HTML dashboard: cookie+CSRF (key HKDF from vault). Cookie Secure per TLS.
- Token rotation bumps persisted `web_state.token_generation`; middleware cache TTL 5s.
- Static embedded via `embed.FS`; HTMX + Alpine + Tailwind precompiled; no Node in build.
- Rate limit per-IP 100/min (loopback exempt) AND per-token 300/min.
- Body limit 1 MiB.
- `/healthz` liveness; `/readyz` readiness (DB + migrations + disk + audit chain tail).
- `http.Server` full timeouts set.
