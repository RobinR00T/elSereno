# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.1] — 2026-04-21

### Fixed — release surface polish
- **cosign bundle**: goreleaser's `signs:` block now passes
  `--bundle=${artifact}.bundle` so the release publishes
  `checksums.txt.bundle` alongside the raw `checksums.txt.sig`.
  Consumers can run `cosign verify-blob --bundle checksums.txt.bundle
  …` without fetching the signing cert out-of-band.
- **SLSA provenance**: bumped `slsa-github-generator` from
  `v2.0.0` → `v2.1.0`. The v2.0.0 finaliser emitted exit 27
  (`SUCCESS=false`) even on a successful upload path, which is
  why v1.0.0 shipped without `.intoto.jsonl` assets. v2.1.0
  (2025-02-24) fixes the false-negative.
- **Pandoc pin**: release workflow installs pandoc 3.9.1 from
  the upstream `.deb` (was distro apt-get). Deterministic man-
  page output removes the reason we had to strip the strict
  "verify man pages in sync" step in the workflow.

### Changed — README
- Badge row (semver release, MIT licence, Go 1.25+, CI status,
  supply-chain status, SLSA 3).
- "Quick install (signed release)" section with the curl +
  shasum -c recipe + optional cosign bundle verification.
- Non-interactive vault-unlock snippet using
  `--vault-passphrase-file` pointing at ADR-026.

## [1.0.0] — 2026-04-20

### Added — F0 Scaffolding (closed 2026-04-19)
- Hexagonal Go 1.23 skeleton: `internal/core`, `internal/config`,
  `internal/exec` with `SafeCommand` + `CommandSpec`, `internal/audit`
  (placeholder chain), `internal/db` (goose migrations embed),
  `internal/render.SafeBytes`.
- Full `.context/` tree: 36 PITFs, 26 ADRs, templates, canonical
  docs, snapshots scaffolding.
- CI pipeline (lint + build ×3 + race/cover + fuzz smoke + sec +
  context-check), Makefile, Dockerfile + Dockerfile.sqlite,
  docker-compose.dev.yml, `.goreleaser.yml`, scripts, man sources.
- Root docs: `README.md`, `SECURITY.md`, `LEGAL.md`, `CONTRIBUTING.md`,
  `CODE_OF_CONDUCT.md`, `NON-GOALS.md`, `TODO.md`, `CLAUDE.md`.

### Added — F1 Inputs/scanner/scoring/triage/observability (closed 2026-04-19)
- Cobra CLI with `version/doctor/legal/plugins/config/scoring/vault/
  creds/db/audit/serve/scan/explain/why/triage/lint/fmt`.
- Koanf loader with unknown-field rejection (`ErrUnknownConfigField`).
- Zerolog with redaction hook (specific patterns + entropy >4.5 b/B +
  UUID v1–v5 exemption, PITF-004).
- Prometheus with low-cardinality label sanitiser (ASN numeric,
  country ISO 3166-1).
- pgx pool with ADR-021 TLS policy; goose migration runner via
  `pgx/v5/stdlib.OpenDBFromPool`.
- Real JCS audit canonicaliser (RFC 8785 via `gowebpki/jcs`).
- Encrypted vault at `~/.elsereno/vault.v1.bin` (AES-GCM +
  Argon2id + HKDF + memguard). CSRF key derived via HKDF from the
  vault master key.
- Scanner: A+AAAA+IDN resolve, dedupe, concurrent probes with global
  + per-host semaphores, token-bucket rate limiting, exponential
  backoff + jitter retries, circuit breaker, 5-minute temporal
  dedupe.
- Triage grouping (quick-win / strategic / routine).
- Outputs: NDJSON (schema `ndjson:v1`), CSV (`csv:v1`), HTML
  (`html:v1`).
- Shodan + Censys HTTP clients.
- Progress bars honouring `NO_COLOR`.
- Outbox worker with dead-letter after `max_attempts`.
- Retention with keep-if-referenced rule encoded in the Pruner
  interface.
- Web server scaffold (full timeouts, security headers, CSP nonces,
  `/healthz`, `/readyz`, CSRF via HKDF).
- banner plugin (first real Protocol).
- Integration test scaffold at `test/integration/` +
  `simulators/docker-compose.test.yml`.

### Added — F2 Legacy telephony (closed 2026-04-19)
- XOT (RFC 1613) plugin + simulator. TPKT/X.25 wire parser with 3
  fuzz targets (ADR-027).
- AT-modem plugin (Hayes / GSM / EN 81-28) + simulator. Line-
  oriented state machine with 64 KiB ceiling and `+CME/+CMS`
  error-code extraction. Vendor dictionary for Siemens, Nokia,
  Sierra, MultiTech, Cinterion, Telit, u-blox, Quectel, Huawei,
  KONE, Otis, Schindler. Proxy blocks ATD*, ATA, AT+CMGS, AT+CMGW,
  AT+CMSS, AT+CMGD, AT+CFUN, AT+CPWROFF, `+++` (ADR-028).
- Milestone: repo pushable to private GitHub.

### Added — F3 Proxy + Modbus (closed 2026-04-19)
- `internal/proxy`: generic TCP framework with Accept + Dial +
  per-connection idle deadline + symmetric Hook interface
  (PreHook with rewrite + PostHook observer). `LoggingHook` routes
  through `render.SafeBytes` (ADR-029).
- Modbus/TCP plugin (ADR-030): from-scratch MBAP + PDU parser,
  FC classifier (read / write / diagnostic / MEI / unknown),
  exception helper, FC 43/14 Device ID decoder, 3 fuzz targets.
  Probe sends FC 1 Read Coils + opportunistic FC 43/14. Proxy
  enforces the write-ban at the wire layer: every CategoryWrite
  FC, non-14 MEI sub-code, or Unknown FC is replied with
  IllegalFunction without touching upstream.
- `simulators/modbus/` (Go) for deterministic CI + pymodbus pointer
  for operator-driven richer scenarios.
- Chaos helpers under `test/chaos/` (`-tags chaos`):
  RandomDropReader, LatencyReader, FlipBitsWriter, EarlyCloser.
- Integration test exercising the proxy framework end-to-end.

### Added — F4 ICS plugins + dashboard + API (closed 2026-04-19)
- Eight new plugins, all with from-scratch wire parsers + probe +
  fuzz + ADR + protocol doc:
  `s7` (TPKT/COTP, 102), `enip` (EtherNet/IP CIP ListIdentity,
  44818), `bacnet` (BVLC Who-Is, UDP/47808), `dnp3` (IEEE 1815
  link frame, 20000), `iec104` (APCI TESTFR, 2404), `hartip`
  (session initiate, 5094), `fox` (Niagara Fox banner, 1911/4911),
  `atg` (Veeder-Root I20100, 10001). 12 plugins registered in the
  default build.
- `banner.DetectVendor()` with Moxa / Lantronix / Digi / NetBurner
  / KONE / Otis / Schindler / OpenSSH rules.
- Dashboard MVP at `/` (inline HTMX-ready HTML listing plugins);
  read-only API at `/api/v1/{plugins,scoring,health}` with envelope
  `{"schema":"api:v1","data":…}`.
- OpenAPI 3.1 spec at `docs/openapi.yaml`.
- Conpot honeypot added to `simulators/docker-compose.test.yml`
  with port maps for all new protocols.
- ADR-031..038.
- Fuzz-found panic in ENIP ListIdentity parser (truncated body)
  fixed with tighter bounds + corpus regression guard.

### Added — F5 Offensive build (closed 2026-04-19)
- ADR-039 triple-confirm wrapper (build tag + `--accept-writes` +
  `--confirm-target` + HMAC-SHA256 token derived via HKDF from the
  vault master key). Every Authorize call emits an audit event —
  allowed, denied, or failed — with payload hash but never the
  plaintext payload.
- ADR-040 per-plugin proxy write-gating. Every TCP-based plugin
  now refuses non-read frames at the wire layer in the default
  build with a protocol-native refusal response (S7 AckData
  err-class 0x85, ENIP status 0x0001, DNP3 FC 15 "Not Supported",
  IEC-104 STOPDT_act, HART-IP session-close status 0x04, ATG
  `9999FF1B` Data-Error). Fox is fail-closed; BACnet (UDP) errors
  immediately under the TCP proxy framework.
- ADR-041 dial guard. Unbypassable ≤3-digit hard block, plus
  scope.yaml `blocked_numbers` prefix/exact match. Wardialing
  batch stays vNext.
- ADR-042 Linux seccomp-bpf sandbox scaffold via pure-Go
  `golang.org/x/sys/unix.Prctl` (`PR_SET_NO_NEW_PRIVS`); BPF
  filter sequences land with F6 subprocess integrations.
- `offensive/write/{modbus,s7,enip,bacnet}` — write plugins with
  deterministic SHA-256 payload hashes. Modbus FC 5/6/15/16; S7
  WriteVar / PLC Stop / PLC Restart; ENIP Set Attribute Single /
  Reset; BACnet WriteProperty (UDP BVLC).
- `offensive/dial/Validate` — three-gate validator (normalise →
  hard ≤3-digit → scope blocked-numbers).
- `offensive/harvest` — Prober interface + four implementations:
  telnet (IAC negotiation + login state machine), ftp (RFC 959),
  http-basic (RFC 7617 with challenge-first), snmp (SNMPv2c
  GetRequest for sysDescr.0 with hand-crafted ASN.1 BER).
- `offensive/exploits` — registry-based harness + two public,
  stable DoS modules: **CVE-2015-5374** (Siemens SIPROTEC 4 /
  Compact EN100 UDP DoS) and **CVE-2019-10953** (Schneider /
  Allen-Bradley / Phoenix Contact CIP ListIdentity DoS).
- `internal/canary` — Sender interface + HTTP sender that POSTs
  `canary:v1` JSON envelopes with optional HMAC-SHA256 signature.
- `internal/scope.(*Scope).CheckDial` — scope side of the dial
  guard.
- `internal/exec.CommandSpec.AllowAnyPath` + `BypassAuditor` —
  `--no-allowlist` escape hatch; refuses to spawn when the
  audit auditor is missing or errors.

### Added — F6 Reporting + release (closed 2026-04-20)
- Five new output sinks: CEF 0.1 (ArcSight; 1..10 severity,
  sorted extensions), RFC 5424 syslog (facility local1 with
  `elsereno@32473` SD-ID), JIRA Cloud REST v3 (ADF description,
  severity→priority mapping), GitHub Issues REST (Bearer PAT +
  2022-11-28 API pin + markdown factor table), and a generic
  HMAC-SHA256-signed webhook.
- HTML report polish: dark-mode palette, per-protocol sections
  with count / max / avg, top-5 factor histogram, severity chips
  with level-specific colours.
- OpenAPI 3.1 autogenerada: `internal/web/openapi.Spec()` is the
  single source of truth; `GET /api/v1/openapi.yaml` serves it
  live; `elsereno api openapi [-o <path>]` refreshes the on-disk
  snapshot.
- Offensive CLI verbs behind `-tags offensive`:
  `elsereno write modbus` (dry-run PDU + payload hash),
  `elsereno exploit list|show|dry-run`,
  `elsereno harvest {telnet,ftp,http-basic,snmp}`,
  `elsereno dial --number <E.164>` with the three-gate
  validator in isolation. Default build unchanged (stub).
- `--vault-passphrase-file <0600 path>` on `vault init`,
  `vault unlock`, `serve`. `os.Lstat` rejects symlinks / pipes /
  devices; mode `perm &^ 0o600 != 0` rejects lax permissions;
  empty-file rejection; CRLF stripping. ADR-026 / PITF-016.
- Operator docs at `docs/protocols/` (12 per-plugin pages +
  README) covering probe bytes, proxy default policy, writes
  behind offensive build, scope + impact, public references.
- Dashboard polish (`/`): dark-mode, plugin grouping (default
  vs offensive), scoring sidebar (ADR-006 weights + severity
  thresholds), auto-refresh pending SSE.
- `RELEASING.md` operator runbook: goreleaser v2 dry-run
  recipe, SBOM via syft (CycloneDX 1.6), cosign keyless
  Sigstore signing + receiver verification, tagging /
  rollback.
- `.goreleaser.yml` migrated `archives.builds` →
  `archives.ids` (goreleaser v2).

### Added — F7 Hardening + 1.0 (closed 2026-04-20)
- Dockers_v2 migration (final goreleaser v2 deprecation cleared)
  + nightly per-target fuzz matrix (30 min per `Fuzz*` target)
  with artefact-uploaded corpora.
- Regression benchmarks: `benchmarks/baseline.txt` checked in;
  benchstat CI comments on every PR with the delta vs base;
  strict mode turns ≥ 10 % regressions into failures.
- OpenTelemetry tracing scaffolding: env-driven exporter
  (`none`/`stdout`/`otlp`), scanner retry/attempt loop emits
  spans with target/port/attempt/plugin attributes.
- 6 STRIDE threat-model docs under `.context/threat-model/`
  (vault-audit, web, scanner-proxy, exec-scope, offensive,
  telemetry-canary) with per-surface residual-risk policy.
- Supply-chain automation at `.github/workflows/supply-chain.
  yml`: OpenSSF Scorecard nightly, SLSA L3 provenance verify
  on tag, dependency-review with licence deny-list (GPL/AGPL/
  LGPL/SSPL/Commons-Clause/Elastic-2.0), osv-scanner,
  licenses-audit artefact.
- `internal/backup`: AES-256-GCM envelope (magic + version +
  salt + nonce + ciphertext) with two-stage HKDF key
  derivation. Salt bound into AEAD AAD so salt-swap attacks
  fail closed. 10 unit tests cover every tamper mode.
- `elsereno backup {create,restore,inspect}` CLI verbs
  honouring `--vault-passphrase-file` for non-interactive
  startup.
- Pentest dashboard panel at `/admin/security`: 11 in-process
  controls with status pills, code-path + ADR references, and
  links to all 6 threat-model docs + every external sec-suite
  job.
- `scripts/release-gate.sh` + `make release-gate`: 11 local
  checks (tests, lint, context, docs, goreleaser snapshot,
  sec-suite, benchmarks baseline) gate the v1.0 tag locally.
- `RELEASING.md` 1.0 section + new `SUPPLY-CHAIN.md` root doc
  with SLSA mapping + dep policy + SBOM diff recipe +
  secrets-rotation table.

### Current phase
**v1.0.0 signed release** is the next milestone (operator
task; `make release-gate` must be green on a clean tree).
See `.context/STATE.md` for authoritative live state,
`.context/snapshots/f7-hardening-1.0.md` for the last
retrospective.
