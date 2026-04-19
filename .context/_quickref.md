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

**Current phase (2026-04-19)**: F0–F5 closed. 29 commits on `main` (no
remote). 12 protocol plugins registered; every TCP-based plugin
enforces a wire-layer write-ban in the default build. F5 adds 4
offensive write modules (modbus/s7/enip/bacnet), 4 harvest probers
(telnet/ftp/http-basic/snmp), 2 CVE DoS exploits (CVE-2015-5374
Siemens SIPROTEC, CVE-2019-10953 CIP), the dial guard with
unbypassable ≤3-digit hard block, the triple-confirm wrapper
(HMAC-SHA256 token derived from vault via HKDF), the canary webhook
sender, and the --no-allowlist exec bypass with mandatory
BypassAuditor. `make ci` green on default + offensive build variants.
Next up: **F6 reporting + release** (HTML pulido, CEF/Syslog/JIRA/
GitHub Issues, webhooks from outbox, dashboard polish + vault UI,
`docs/protocols/*`, signed 0.1.0 release, repo público).
