# ElSereno Roadmap

Live state is in `.context/STATE.md`; per-phase retrospectives in
`.context/snapshots/`. Forward-looking roadmap (post-1.0 features
+ what's missing from the brief) lives in [`ROADMAP.md`](ROADMAP.md).
This file tracks the brief's original checklist so the delta
between planned and shipped stays visible.

## v1.0 — released 2026-04-20 + 2026-04-21

- [x] **v1.0.0 signed tag** — 12 release assets at
  `RobinR00T/elSereno` (private). GPG signature
  ACE3B86BACACE7D6.
- [x] **v1.0.1 polish** — cosign bundle (verified end-to-end
  with `cosign verify-blob --bundle`) + SLSA v2.1.0 + pandoc
  3.9.0.2 pin + README badges.
- [ ] **Flip repo to public** — operator decision; unlocks
  Scorecard + CodeQL + OSV full suite.
- [ ] **Revoke the bootstrap PAT** — operator task at
  https://github.com/settings/personal-access-tokens. User
  asked to keep it live until end of v1.1.

## v1.1 — in flight on `main`

- [x] Chunk 1: per-plugin offensive `WriteGatedHandler` ×9
  (ADR-040 close).
- [x] Chunk 2: file-backed audit writer
  (`internal/audit/FileWriter`) + `offensive/confirm/adapter`.
- [x] Chunk 3: network delivery for `write modbus send` /
  `exploit run` / `audit verify-file`.
- [x] Chunk 4a: SSE `/api/v1/stream` + broadcaster + dashboard
  live-feed panel + audit file tailer for cross-process feed.
- [ ] Chunk 4b (carry-over to v1.2): findings/triage/runs DB
  tables + panels reading from DB (lands with DB-backed Writer).
- [x] Chunk 5: GHCR docker image (buildx + `robinr00t/elsereno`
  slug + `--attest=type=sbom` via `dockers_v2 sbom: true` +
  cosign keyless `docker_signs`, go 1.25.4 Dockerfile pin).
- [x] Chunk 6: seccomp-bpf BPF filter bytecode per profile
  (exploit/harvest/dial). `offensive/sandbox` compiles denylist
  BPF programs for x86_64 + arm64, installs via
  `seccomp(SET_MODE_FILTER, TSYNC)`, records `offensive_sandbox`
  audit entries via new migration 00002. Wired into
  write/exploit/harvest CLI verbs.
- [x] Chunk 7: OPC UA plugin (port 4840) — UA-TCP HEL/ACK/ERR
  parser + probe + simulator + default deny-all proxy with
  UA-native ERR refusal. Write gating carry-over to v1.2.
- [x] Chunk 8: Wardialing batch mode — `elsereno dial batch
  --numbers-file <path> --scope <scope.yaml>` classifies every
  number against the ADR-041 guard, installs the seccomp `dial`
  profile, and appends one audit entry per decision. Real
  PSTN / VoIP delivery is a v1.2 carry-over.
- [ ] v1.1 close + signed tag v1.1.0.

## Post-1.0 roadmap

Top priorities (full detail + effort estimates in `ROADMAP.md`):

- **P1** — DB-backed audit writer + `elsereno write|exploit|
  harvest|dial` network delivery wiring.
- **P1** — Per-plugin offensive `WriteGatedHandler` substitution
  for 8 protocols (ADR-040 carry-over).
- **P1** — SSE `/api/v1/stream` + findings/triage/runs DB
  panels replacing the dashboard placeholder.
- **P2** — GHCR docker image (buildx + correct slug +
  `--attest=type=sbom`).
- **P2** — seccomp-bpf filter bytecode per profile.
- **P2** — OPC UA plugin (most-asked next protocol).
- **P2** — Wardialing batch mode.

## Phase 0 — Scaffolding — ✅ closed 2026-04-19
- [x] Estructura de repo sección 6
- [x] go.mod con path + toolchain exacta (`local/elsereno`, `go1.23.4`)
- [x] cmd/elsereno/main.go con signal.NotifyContext + exit 128+signum + cobra
- [x] internal/core con interfaces + entidades + value types + errors
- [x] internal/bus estructura (findings CopyFrom + audit sequential wire-in lands in F1 chunk 2)
- [x] internal/config con Koanf + validator + unknown-fields rejector + ErrUnknownConfigField
- [x] internal/db con pool pgx + goose + migración 00001 completa
- [x] internal/audit con genesis + tombstone + rebase + JCS + ErrChainBroken
- [x] internal/render SafeBytes
- [x] internal/telemetry zerolog + redaction hook + UUID exclusion + prometheus + label sanitizer
- [x] internal/scoring interfaces + YAMLs defaults
- [x] internal/web http.Server full timeouts + CSRF HKDF + security headers
- [x] internal/scope opcional + CIDR v4/v6
- [x] internal/creds vault AES-GCM+Argon2id+HKDF+memguard + file-backed + env-TTY warning
- [x] internal/doctor runtime+CAP_NET_RAW/root+nmap+DNS+IPv6+disk
- [x] internal/exec SafeCommand + CommandSpec + path allowlist + `--` determinista
- [x] cmd plugins.go + plugins_offensive.go
- [x] .env.example alineado con docker-compose trust auth
- [x] .golangci.yml v2 con lista completa de linters
- [x] .goreleaser.yml
- [x] CI ci.yml + release.yml + nightly.yml + codeql.yml + dependabot + renovate
- [x] Makefile completo (ci superset)
- [x] Dockerfile pinned (Dockerfile.sqlite retired in v1.2 — Postgres-only)
- [x] docker-compose.dev.yml Postgres 16 + Adminer
- [x] .devcontainer · lefthook · .gitignore · .editorconfig · .gitleaks.toml
- [x] Documentación raíz (README/SECURITY/LEGAL/CONTRIBUTING/CODE_OF_CONDUCT/NON-GOALS/CHANGELOG)
- [x] .context/ completo (INDEX, STATE, _quickref, conventions, pitfalls 001-036, decisions 001-026, templates, snapshots, protocols placeholders)
- [x] scripts/context-check.sh (valida pitfalls ≥36 + detector PITF-007)
- [x] scripts/gen-manpages.sh
- [x] scripts/install-hooks.sh
- [x] scripts/run-fuzz.sh
- [x] man/src/man5 + man/src/man7 markdown sources
- [x] doc.go en cada paquete
- [x] `make ci` verde end-to-end

## Phase 1 — Inputs, scanner, scoring, triage, observability — ✅ closed 2026-04-19
- [x] Inputs Shodan/Censys/nmapxml/list/stdin
- [x] Scanner async con resolve A+AAAA+IDN+dedupe + rate limits + jitter + retries + circuit breaker + temporal dedup (5 min)
- [x] Scoring engine v1 con weights ADR-006
- [x] triage grouping quick-wins/strategic/routine
- [x] explain / why / lint / fmt CLI verbs
- [x] Outputs NDJSON/CSV/HTML
- [x] Progress bars ETA + NO_COLOR
- [x] Prometheus poblada + label sanitizer activo
- [x] Retention keep-if-referenced (Pruner interface)
- [x] Outbox retry+backoff+dead-letter (MemStore; Postgres Store F5)
- [x] Tests IPv6 (scaffold integración; loopback end-to-end)
- [x] Cobra CLI rewire (F1 chunk 1)
- [x] Vault file-backed (~/.elsereno/vault.v1.bin)
- [x] JCS real audit chain (RFC 8785 via gowebpki/jcs)

## Phase 2 — XOT + AT modems — ✅ closed 2026-04-19
### 2a XOT
- [x] Parser XOT RFC 1613 (wire/)
- [x] Fingerprint CALL REQUEST / CLEAR / Call Accepted
- [ ] REPL call/clear/data + PAD X.29 (deferred to F4 chunk 2 generic REPL)
- [x] Proxy pass-through
- [x] Simulador simulators/xot/
- [x] Fuzz targets (3)
- [x] ADR XOT (027)
### 2b atmodem
- [x] Parser AT lines+multiline+CME/CMS
- [x] Fingerprint Hayes+GSM+vendor+EN 81-28
- [ ] Read-only info/config/network/signal/imsi/imei audit-per-op (deferred to F4 chunk 2 REPL)
- [ ] REPL AT con history+tab-completion (deferred to F4 chunk 2)
- [x] Proxy bloqueo ATD*/ATA/AT+CMGS/CMGW/CMSS/CMGD/CFUN/CPWROFF/+++
- [x] Simulador simulators/atmodem/
- [x] Fuzz targets (2)
- [x] ADR atmodem (028)
### Hito F2
- [x] Repo pushable a GitHub privado (operator push pending)

## Phase 3 — Proxy + Modbus — ✅ closed 2026-04-19
- [x] Framework proxy TCP con hooks pre/post (UDP sigue cuando haga falta)
- [x] Plugin Modbus read-only (FC 1-4 forward; writes blocked at wire layer)
- [x] Suite adversarial FC-by-FC (write FCs 5/6/15/16/22/23)
- [x] Chaos helper test/chaos/ (build tag chaos)
- [x] Simulador modbus-sim (Go) + pymodbus pointer

## Phase 4 — Resto ICS + Dashboard — ✅ closed 2026-04-19
- [x] Plugins S7 / ENIP / BACnet / DNP3 / IEC-104 / HART-IP / Fox / ATG / banner+dict
- [x] Conpot en docker-compose.test.yml
- [x] Dashboard overview (inline HTMX; findings/triage/runs/scope/protocols panels in F4 chunk 2)
- [ ] SSE live scans (F4 chunk 2)
- [ ] TUI bubbletea (F4 chunk 2)
- [x] API /api/v1 (plugins/scoring/health read-only) + OpenAPI 3.1 in docs/

## Phase 5 — Offensive (build tag) — ✅ closed 2026-04-19
- [x] Writes Modbus/S7/CIP/BACnet triple confirm
- [x] Exploits arch + 2 CVE público estable (CVE-2015-5374, CVE-2019-10953)
- [x] Harvest Telnet/FTP/HTTP-Basic/SNMPv1-2c → vault (prober interface + 4 impls; CLI lands F6)
- [x] Dial individual + blacklist ≤3 dígitos hard + scope.yaml.blocked_numbers
- [x] Sandbox seccomp-bpf Linux (ADR-042; PR_SET_NO_NEW_PRIVS; BPF filter instruction sequences ship F6)
- [x] --no-allowlist bypass con audit trail (internal/exec.CommandSpec.AllowAnyPath + BypassAuditor)
- [x] Canary scope.yaml webhook (internal/canary; HMAC-SHA256 signed)
- [x] Per-plugin proxy write-gating for the 7 F4 plugins (s7, enip, bacnet, dnp3, iec104, hartip, fox, atg)

## Phase 6 — Reporting + release — ✅ closed 2026-04-20
- [x] HTML pulido (dark-mode, per-protocol sections, factor histogram)
- [x] CEF/Syslog/JIRA/GitHub Issues output sinks
- [x] OpenAPI autogenerada (`internal/web/openapi.Spec()` + `elsereno api openapi` + live `/api/v1/openapi.yaml`)
- [x] Webhooks genéricos con firma HMAC-SHA256
- [x] Dashboard pulido (grouped plugins, scoring sidebar, severity chips, dark-mode)
- [x] `docs/protocols/*` (12 plugins + README)
- [x] `--vault-passphrase-file` (ADR-026 / PITF-016) para non-interactive startup
- [x] Offensive CLI wiring: `elsereno write|exploit|harvest|dial` behind `-tags offensive`
- [x] RELEASING.md runbook + goreleaser v2 dry-run validado (8 binaries + SBOM + checksums)
- [ ] Release 0.1.0 firmada (tag + cosign + publish — operator task)
- [ ] Repo público (operator push)

## Phase 7 — Hardening + 1.0 — ✅ closed 2026-04-20
- [x] Fuzz exhaustivo nightly (per-target matrix, 30 min each)
- [ ] Gremlins mutation (deferred post-1.0; scorecard covers measurement)
- [x] STRIDE por módulo (6 threat-model docs)
- [x] Pentest dashboard (`/admin/security` self-audit panel)
- [x] Supply chain audit (scorecard + SLSA L3 + dep-review + osv + licenses)
- [x] OTel tracing (scaffold + scanner spans)
- [x] Backup automation cifrado (internal/backup + CLI verbs)
- [x] Regresión benchmarks CI (benchstat + auto-comment)
- [x] `make release-gate` + RELEASING.md 1.0 section + SUPPLY-CHAIN.md
- [ ] Release 1.0.0 signed tag (operator task — run `make release-gate`, push tag)
- [ ] Repo público (operator task post-1.0)

## vNext
- [ ] L2 PROFINET DCP/GOOSE/SV con gopacket
- [ ] OPC UA/CoDeSys/Omron FINS/MELSEC SLMP/PCWorx/ProConOS/Crimson/GE-SRTP/IEC 61850 MMS/KNX/M-Bus
- [ ] Windows support
- [ ] Multi-user OIDC + roles
- [ ] Record & replay sesiones
- [ ] MITM transparente con routing
- [ ] ONYPHE/Fofa/Zoomeye/Shodan InternetDB inputs
- [ ] STIX 2.1 export
- [ ] Wardialing batch con scope file
