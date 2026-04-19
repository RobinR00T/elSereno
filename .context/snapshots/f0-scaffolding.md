---
phase: F0
date: 2026-04-19
token-budget: 1000
---

# Phase F0 snapshot — Scaffolding

## Shipped

- Repository structure per project brief section 6 (85 directories).
- Git initialised with default branch `main`.
- `go.mod` with module path `local/elsereno`, `go 1.22`, toolchain
  `go1.23.4`.
- `cmd/elsereno` with signal handling (`signal.NotifyContext`,
  `128+signum` exit codes), dispatch, version/help/doctor/legal/plugins
  wired, all other F0 verbs stubbed behind a clear tempfail message.
- `internal/core`: interfaces, entities, value types (`Port`, `Severity`,
  `Confidence`, `ExitCode`), shared sentinels, plugin registry.
- `internal/exec.SafeCommand` with `CommandSpec{Name, Flags, Positional}`,
  path allowlist, deterministic `--` separator, metachar rejection.
- `internal/render.SafeBytes` with C0/C1/DEL picturing and ESC handling.
- `internal/audit`: `ErrChainBroken`, enumerated `EventType` constants
  mirroring the SQL CHECK, canonical-fields enumeration, genesis prev-hash
  sentinel, `IsProtectedMetadata` helper.
- `internal/config`: `Config` struct, `ErrUnknownConfigField`,
  `Defaults()` covering every field called out in the brief.
- `internal/telemetry.SafeField` for target-controlled strings at the
  log boundary.
- `doc.go` in every internal and offensive package.
- `migrations/00001_initial.sql`: full DDL with `web_state`, `outbox_dead`,
  `audit_log.event_type` enum, `ON DELETE RESTRICT` on
  `audit_purge_markers.audit_entry_id`, and the keep-if-referenced
  evidence contract.
- `.context/` tree: `CLAUDE.md`, `_quickref.md`, `STATE.md`,
  `conventions.md`, `pitfalls.md` (PITF-001..036), `INDEX.md`,
  `CHANGELOG.md`, `architecture.md`, `glossary.md`, `scoring.md`,
  `persistence.md`, `web.md`, `testing-strategy.md`, `security-model.md`,
  `decisions/001..026`, `protocols/_index.md` plus 12 placeholders,
  `templates/{pitfall,protocol,adr,snapshot}.md`.
- Root docs: `README.md`, `LEGAL.md`, `SECURITY.md`, `CONTRIBUTING.md`,
  `CODE_OF_CONDUCT.md`, `NON-GOALS.md`, `CHANGELOG.md`, `TODO.md`,
  `LICENSE`.
- Build infra: `.golangci.yml`, `.gitignore`, `.editorconfig`,
  `.env.example`, `.gitleaks.toml`, `.goreleaser.yml`, `lefthook.yml`,
  `renovate.json`, `.devcontainer/devcontainer.json`.
- CI workflows: `ci.yml`, `release.yml`, `nightly.yml`, `codeql.yml`,
  `dependabot.yml`, pull-request and issue templates.
- `Makefile` with the full target set; `ci` target is the local superset
  (PITF-031).
- `Dockerfile` pinned to `golang:1.23.4-alpine3.20`, distroless runtime;
  `Dockerfile.sqlite` with CGO and SQLCipher; `docker-compose.dev.yml`
  with `postgres:16.3-alpine3.20` on explicit loopback bind + Adminer.
- Scripts: `context-check.sh` (self-aware detector), `gen-manpages.sh`
  (cobra man1 + pandoc man5/7), `install-hooks.sh`, `run-fuzz.sh`.
- Man sources: `man/src/man5/{elsereno.yaml,elsereno-scope,elsereno-scoring}.md`;
  `man/src/man7/{elsereno-protocols,elsereno-security}.md`.
- Tests: SafeCommand, SafeBytes, value-type, and migration-vs-Go-events
  drift tests (green under `go test -race -count=1 ./...`).

## Non-trivial decisions made

- ADR-001..026 as shipped in `.context/decisions/`.
- Scaffold deliberately stdlib-only so `go build ./...` works without
  network access to dependency caches (PITF-011 discipline: pgx, koanf,
  zerolog, cobra, etc. are wired in F1 after per-dep maintenance-state
  verification).
- The F0 audit canonicaliser uses a SHA-256 over a pipe-delimited
  encoding as a placeholder; a JCS-backed replacement lands in F1
  (ADR-015) with migration-test coverage.

## New pitfalls captured

None beyond the initial PITF-001..036 already captured in the brief.

## Debt accepted

- `make ci` closed green on 2026-04-19 after installing golangci-lint
  v2.11.4, gosec, govulncheck, go-licenses, trivy 0.70, gitleaks 8.30,
  pandoc, sqlcipher. `.golangci.yml` had to be rewritten for v2 config
  schema (v1 format was rejected). `.gitleaks.toml` tightened so the
  empty-value placeholders in `.env.example` no longer self-match
  (regression guard for PITF-010 — rule required `\S+` after `=`; paths
  allowlist also skips the file).
- Cobra is not wired: F0 uses a hand-rolled dispatcher. Cobra replaces it
  in F1 together with `cobra/doc`-generated man1 pages.
- Koanf loader is not wired; `internal/config` ships the type surface
  only. The unknown-fields rejector (`ErrUnknownConfigField`) lives in
  the package sentinel set so callers compile against it today.
- `internal/web` is structure-only (no real http.Server yet).
- `internal/creds` is structure-only; memguard + Argon2id + HKDF arrive
  in F1 along with the vault sub-commands.

## What moves to next phase (F1)

- Replace hand-rolled CLI with cobra + `cobra/doc` (man1).
- Wire pgxpool, goose migrations, koanf loader, zerolog with redaction
  hook, Prometheus + OTel, `gorilla/csrf` with HKDF, `memguard` vault.
- Implement the first protocol-free verbs (`doctor`, `init`, `db
  migrate/status/verify`, `audit verify/purge/compact`,
  `vault init/unlock/lock/status`, `creds store/...`, `serve` placeholder
  requiring a live vault, `token rotate/show`).
- Land F1 scope (Shodan/Censys/nmap/list/stdin inputs, scanner, scoring,
  triage, NDJSON/CSV/HTML outputs, Prometheus populated, outbox with
  max_attempts + dead letter, retention keep-if-referenced).
- Only then close F0 by running `make ci` green on the operator's
  machine.
