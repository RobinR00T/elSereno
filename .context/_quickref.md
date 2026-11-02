---
phase: any
status: canonical
last-updated: 2026-10-18
token-budget: 950
---

# ElSereno, Quick Reference

**What**: ICS/OT legacy exposure scanner + fingerprinter + proxy + REPL + dashboard + interactive TUI. Defensive default; `-tags offensive` for writes/exploits/harvest/dial. Three build variants since v1.29: default / offensive / mini (mini excludes dashboard + TUI for device deployments).

**Stack**: Go 1.26+ (go.mod `go 1.26.0`; keep Dockerfile GO_VERSION + ci.yml matrix minimum + `.devcontainer` image in sync, enforced by `scripts/check-version-sync.sh` in the audit job: see PITF-061), Postgres 16, HTMX+Alpine+Tailwind, single static binary (pure Go, no CGO). Linux + macOS only.

**Key invariants**:
- Default build read-only. Writes require `-tags offensive` + triple-confirm.
- Dialing is offensive-only; recording delivery intent (`--disposition delivery-requested`) requires `--dial-allowed` (dial validate validates; batch/wardial validate, classify and audit; hardware delivery is vNext). ≤3-digit numbers blocked.
- `scope.yaml` applies only with `--scope`, which every network command takes since 2026-10-17 (scan, serve, discover, fingerprint probe, plaintext-check, tui --input, opcua/s7 probes, write send, exploit run, proxy listen, harvest, creds-check, dial): ranges + ports on the target, protocols on the plugin (name or family before "-"), blocked_numbers in dial (number and entry normalised, so + and 00 work); single-target refusal = 77, write-class verbs need an IP literal; binds.allow applied on serve with --scope, canary parsed not applied; no auto-load, no AUP prompt (PITF-087, PITF-095).
- Parsers from scratch in `internal/protocols/<name>/wire/`.
- Hexagonal: `core` only stdlib.
- Plugins register in `init()` via `core.Register(...)`.
- Findings: one `INSERT` per finding (`serve`, `internal/repo/runwriter.go`); the batched `pgx.CopyFrom` path of ADR-008 is not built. Audit: appended in order to `~/.elsereno/audit.jsonl` by one writer; the Postgres audit writer (`OpenDBWriter`) exists but no command wires it.
- Scoring 0-100 multi-factor (ADR-006).
- Audit JCS hash chain; genesis `prev_hash=0x00..00`; canonical `id/occurred_at/actor/event_type/payload/prev_hash`; tombstone purge preserves chain; compact inserts rebase marker and skips metadata entries. `event_type` is CHECK enum.
- Postgres TLS per `database.tls_required` ∈ {auto, always, disable}.
- Web: OIDC Bearer JWT on the routes with a role when configured (required off loopback; `/`, `/admin/security`, `/metrics`, `/healthz`, `/readyz` and `GET /api/v1/{plugins,scoring,health,health/pool,openapi.yaml}` stay open); dev mode on loopback has no auth; a browser guard refuses cross-origin writes, non-JSON write bodies and DNS rebinding (PITF-092). Cookie, CSRF token, web token and `web_state` rotation are designed, not built (PITF-087).
- Vault: `init` → `unlock` → ops. Key in memguard inside the process that opened it (`serve`, offensive runtime); one-shot `unlock` only checks the passphrase, `lock` is a no-op.
- Rate limit per-IP 100/min (loopback exempt) AND per-token 300/min, in serve since 2026-10-18 (PITF-100); 429 + Retry-After: 60.
- `crypto/rand` only. Subprocess via `internal/exec.SafeCommand(ctx, CommandSpec)` with deterministic `--` separator (rule; no command spawns one yet).
- Timestamps RFC3339 up to 6 fractional digits (microseconds). Logs stderr, data stdout.
- IPv4+IPv6 first-class; IDN via `x/net/idna`.
- SIGINT→130, SIGTERM→143. Second signal immediate same code.
- Evidence truncated with `original_sha256` (populated only when truncated); retention keep-if-referenced.
- Outbox: `internal/outbox` has a retry worker (max_attempts, dead-letter) and an in-memory store; the `outbox`/`outbox_dead` tables exist in the schema, but no Postgres store and no command wires it (webhooks and exports deliver inline).
- Redaction hook: specific patterns + entropy heuristic excluding UUID format (`telemetry.Redact` per field; `telemetry.RedactWriter` on the standard logger's sink since 17-10, so every `log.Printf` is redacted; PITF-099).
- Errors in emitting package.
- Never secrets via argv, herestring, or unwarned env.
- `make ci` must include build variants to catch bitrot.

**Before touching code**: read `pitfalls.md`.

**First command when in doubt**: `elsereno doctor`.

**Current phase**: see `.context/STATE.md` (authoritative). As of
2026-10-19 the last tag is `v2.63.2`, released by CI with cosign keyless,
SLSA v1 provenance and a public signed GHCR image (PITF-102, PITF-103).

**Counts** (authoritative: `elsereno plugins list`): **35
protocol plugins** in the default build (2026-10-18); **24 offensive write-gated
proxies** (incl. the legacy-ICS set finsudp/slmp/gesrtp/codesys/
redlion, landed 2026-08/09); **7 attack-surface input clients**
(shodan, censys, fofa, zoomeye, onyphe, binaryedge, internetdb;
the last is no-key + single-IP/bulk-lookup). Default-build proxy
handlers (write-ban, fail-closed, deny-all or XOT pass-through; see
`docs/protocols/README.md`) are not served by any command (`elsereno
proxy` is a stub; PITF-087). The core
gates carry per-object / per-path scoping as of
v1.12 + v1.13: Modbus structured writes + FC 8 diag
sub-function gate, OPC UA per-NodeId
(numeric + String/GUID/ByteString) + per-CallMethod, BACnet
per-WriteProperty + per-WPM + per-DeleteObject, SIP
per-method/prefix/AOR/from-domain, CWMP per-RPC + per-param-
prefix + per-firmware-URL, IAX2 per-subclass, pbxhttp per-
(method, path), DNP3 per app-FC + per-CROB (index, control-
code) + broadcast-deny + link-address pin.

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
preview. **Proxy session capture**: `proxy listen --record FILE`
(v1.30) wires `replay.Recorder` into all 9 wire-aware gates;
`elsereno proxy replay FILE` renders captures.

**Interactive TUI** (`elsereno tui`, default + offensive
builds; not in mini): bubbletea-based 4-pane layout (findings /
triage / audit / scan progress). Five modes: interactive
(default empty; or `--input KIND` runs Scanner inside TUI),
`--replay FILE.ndjson`, `--feed -` (stdin),
`--watch URL --bearer TOKEN` (SSE). `--input` accepts the
same 8 kinds as `scan` since v1.31 (list:, nmap:, stdin,
shodan:, censys:, fofa:, zoomeye:, onyphe:, internetdb:).
`/` filters audit pane substring (case-insensitive); Tab
cycles focus; j/k/g/G navigate findings; q quits.

**Supply chain**: Free-tier release flow since v1.8 (GPG-signed
tag + SHA-256 + CycloneDX SBOM via local goreleaser + `gh
release upload`); cosign keyless + SLSA v1.0 + GHCR docker
remain available behind GitHub Actions billing restore. Pentest
self-audit panel at `/admin/security`. `make sec` exit 0 since
2026-04-25 (`b611f5c` swapped 18 `//nolint:gosec` → native
`// #nosec G<NNN>`).
