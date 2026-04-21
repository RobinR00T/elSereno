---
phase: any
status: canonical
last-updated: 2026-04-19
token-budget: 900
---

# ElSereno — Quick Reference

**What**: ICS/OT legacy exposure scanner + fingerprinter + proxy + REPL + dashboard. Defensive default; `-tags offensive` for writes/exploits/harvest/dial.

**Stack**: Go 1.22+, Postgres (SQLite portable via tag), HTMX+Alpine+Tailwind, single static binary. Linux + macOS only.

**Key invariants**:
- Default build read-only. Writes require `-tags offensive` + triple-confirm.
- Dialing requires `-tags offensive` + `--dial-allowed`. ≤3-digit numbers blocked. Wardialing batch vNext.
- `scope.yaml` optional; AUP ack when absent.
- Parsers from scratch in `internal/protocols/<name>/wire/`.
- Hexagonal: `core` only stdlib.
- Plugins register in `init()` via `core.Register(...)`.
- Findings: CopyFrom batched. Audit: sequential INSERT single-threaded.
- Scoring 0–100 multi-factor (ADR-006).
- Audit JCS hash chain; genesis `prev_hash=0x00..00`; canonical `id/occurred_at/actor/event_type/payload/prev_hash`; tombstone purge preserves chain; compact inserts rebase marker and skips metadata entries. `event_type` is CHECK enum.
- Postgres TLS per `database.tls_required` ∈ {auto, always, disable}.
- Web: Bearer `/api/v1/*`; cookie+CSRF (HKDF from vault) HTML. Cookie `token_generation` persisted in `web_state`; bumped with advisory lock; middleware cache TTL 5s.
- Vault: `init` → `unlock` → ops; `lock` zeroizes. Unlock-once memguard.
- Rate limit per-IP 100/min (loopback exempt) AND per-token 300/min.
- `crypto/rand` only. Subprocess via `internal/exec.SafeCommand(ctx, CommandSpec)` with deterministic `--` separator.
- Timestamps RFC3339 up to 6 fractional digits (microseconds). Logs stderr, data stdout.
- IPv4+IPv6 first-class; IDN via `x/net/idna`.
- SIGINT→130, SIGTERM→143. Second signal immediate same code.
- Evidence truncated with `original_sha256` (populated only when truncated); retention keep-if-referenced.
- Outbox with max_attempts + `outbox_dead`.
- Redaction hook: specific patterns + entropy heuristic excluding UUID format.
- Errors in emitting package.
- Never secrets via argv, herestring, or unwarned env.
- `make ci` must include build variants to catch bitrot.

**Before touching code**: read `pitfalls.md`.

**First command when in doubt**: `elsereno doctor`.

**Current phase (2026-04-21)**: v1.0.0 tagged + signed release
published at RobinR00T/elSereno (private). v1.0.1 polish queued
(cosign bundle, SLSA v2.1.0 generator, pandoc 3.9.0.2 pin, README
badges). F0–F7 closed; ~60 commits on `main`.
12 protocol plugins in the default build; every TCP-based plugin
enforces a wire-layer write-ban. 5 output sinks (NDJSON / CSV /
HTML-polished / CEF / Syslog) plus 3 ticketing / webhook sinks
(JIRA / GitHub Issues / generic webhook with HMAC). OpenAPI 3.1
is now code-sourced (`internal/web/openapi.Spec`) and served live
on `/api/v1/openapi.yaml`; `elsereno api openapi -o docs/openapi.yaml`
refreshes the snapshot. The offensive CLI (`write|exploit|harvest|
dial`) is operator-usable behind `-tags offensive`; network delivery
carries over to F7 once the DB-backed audit writer ships.
`--vault-passphrase-file <0600 path>` unblocks CI/preview.
Dashboard at `/` is polished (dark-mode, plugin grouping, scoring
sidebar, severity thresholds). `RELEASING.md` ships the operator
runbook for a signed 0.1.0 tag; dry-run produces 8 binaries
(darwin + linux × amd64 + arm64 × default + offensive) with SBOM
(CycloneDX 1.6, 48 components) and SHA-256 checksums.
`make ci` green on both build variants.
F7 adds: dockers_v2, nightly per-target fuzz matrix, regression
benchmarks with benchstat, OpenTelemetry tracing, 6 STRIDE
threat-model docs, supply-chain automation (scorecard + SLSA L3 +
dep-review + osv-scanner), encrypted backup package + CLI verbs,
pentest self-audit panel at `/admin/security`, and
`make release-gate` local green-light. Next up: **v1.0.0 signed
tag** (operator task; prerequisites in `RELEASING.md`).
