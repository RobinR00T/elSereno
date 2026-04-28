---
phase: any
status: canonical
last-updated: 2026-04-28
token-budget: 900
---

# ElSereno — Quick Reference

**What**: ICS/OT legacy exposure scanner + fingerprinter + proxy + REPL + dashboard. Defensive default; `-tags offensive` for writes/exploits/harvest/dial.

**Stack**: Go 1.25+, Postgres 16, HTMX+Alpine+Tailwind, single static binary (pure Go, no CGO). Linux + macOS only.

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

**Current phase (2026-04-28)**: **v1.20 cycle closed on `main`,
tag pending operator**. 3 chunks: legacy ICS fingerprint
trio — Omron FINS UDP/9600 (chunk 1), MELSEC SLMP TCP/5007
(chunk 2), GE-SRTP TCP/18245 (chunk 3). Default build now
registers **20 protocol plugins** (was 17). 56 new tests.
Snapshot:
`.context/snapshots/v1.20.0-legacy-ics-fingerprint-trio.md`.
v1.16 / v1.17 / v1.18 / v1.19 cycles also closed (tags
pending). v1.15.0 still the latest published release.

**Counts**: **20 protocol plugins** in the default build; **7
offensive write-gated proxies** (modbus, opcua, sip, iax2,
pbxhttp, bacnet, cwmp); **6 attack-surface input clients**
(shodan, censys, fofa, zoomeye, onyphe, internetdb — last is
no-key + single-IP/bulk-lookup since v1.13 chunk 1). Every
TCP-based plugin enforces a wire-layer write-ban in default
mode. **All 7 gates carry per-object / per-path scoping** as of
v1.12 + v1.13: Modbus structured writes, OPC UA per-NodeId
(numeric + String/GUID/ByteString) + per-CallMethod, BACnet
per-WriteProperty + per-WPM + per-DeleteObject, SIP
per-method/prefix/AOR/from-domain, CWMP per-RPC + per-param-
prefix + per-firmware-URL, IAX2 per-subclass, pbxhttp per-
(method, path).

**Outputs**: 5 sinks (NDJSON / CSV / HTML / CEF / Syslog) + 3
ticketing/webhook sinks (JIRA / GitHub Issues / generic HMAC
webhook). **OpenAPI 3.1** code-sourced (`internal/web/openapi.Spec`),
served live on `/api/v1/openapi.yaml`. **Triage**: 4-bucket
priority since v1.13 chunk 6 (quick_win → strategic → utility
→ routine).

**Offensive CLI** (`write|exploit|harvest|dial`) operator-usable
behind `-tags offensive`. Network delivery, DB-backed audit
writer, SSE feed, dashboard live-feed all shipped. CWMP
firmware pre-flight verifier
(`elsereno-offensive write cwmp verify-firmware`) since v1.13
chunk 2. `--vault-passphrase-file <0600 path>` unblocks CI/
preview.

**Supply chain**: Free-tier release flow since v1.8 (GPG-signed
tag + SHA-256 + CycloneDX SBOM via local goreleaser + `gh
release upload`); cosign keyless + SLSA v1.0 + GHCR docker
remain available behind GitHub Actions billing restore. Pentest
self-audit panel at `/admin/security`. `make sec` exit 0 since
2026-04-25 (`b611f5c` swapped 18 `//nolint:gosec` → native
`// #nosec G<NNN>`).
