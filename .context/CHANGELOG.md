---
phase: any
status: living
last-updated: 2026-04-19
---

# Context changelog

One-liner per significant change to `.context/` or the codebase.

- 2026-04-19 — F0 — Scaffolding initialised. Context system populated with
  36 PITFs, 26 ADRs, templates, and per-topic canonical docs. Repository
  tree created per section 6 of the project brief.
- 2026-04-19 — F0 — **Closed.** `make ci` green end-to-end on operator's
  machine: golangci-lint v2 (0 issues), build × 3 variants, race + cover,
  fuzz smoke (2 targets: SafeBytes, SafeCommand flag validator), sec
  (gosec 0, govulncheck 0, trivy 0, go-licenses 0, gitleaks 0),
  context-check. .golangci.yml ported to v2 config format;
  .gitleaks.toml tightened so empty .env.example placeholders no longer
  trigger (regression guard for PITF-010).
- 2026-04-19 — F1 (chunk 1) — cobra rewires cmd/elsereno with a real
  verb tree (version/doctor/legal/plugins/config/scoring) and typed
  stubs for the rest. Koanf loader with struct-tag walker rejects
  unknown YAML keys via ErrUnknownConfigField. Zerolog logger +
  Redact(key, value) with entropy heuristic (>4.5 bits/byte) and a
  UUID v1–v5 exemption (PITF-004). pgx pool enforces
  database.tls_required per ADR-021. Goose migration runner wired to
  embedded SQL (stdlib bridge pending chunk 2). Inputs: list, stdin,
  nmapxml. Outputs: NDJSON (ndjson:v1) and CSV (csv:v1). Scoring engine
  v1 with embedded defaults/weights.yaml (ADR-006). Doctor checks go
  runtime, platform, CAP_NET_RAW / root, nmap presence, IPv6, and disk.
  `make ci` green again.
- 2026-04-19 — F1 (chunk 2) — vault (AES-GCM + Argon2id + HKDF +
  memguard) with unlock-once, Lock zeroisation, Init refuses silent
  re-init; goose migrations runnable via pgx stdlib bridge
  (OpenDBFromPool); Prometheus metrics (findings_total,
  scan_duration_seconds, persistence_lag_seconds, audit_entries_total,
  outbox_inflight) + label sanitiser (protocol / severity to a fixed
  set; ASN numeric; country ISO 3166-1 alpha-2; else "unknown");
  scanner core with resolve (A+AAAA+IDN), Dedupe, concurrent probes
  with per-host + global semaphores, token-bucket rate limiting,
  exponential backoff+jitter retries; triage grouping
  (quick_win/strategic/routine); HTML output (html:v1); Shodan REST
  client. `make ci` green. F1 snapshot written.
- 2026-04-19 — F1 (chunk 3) — **F1 closed.** CLI wiring for
  vault/creds/db/audit/serve/scan/explain/why/triage/lint/fmt. File-
  backed vault at ~/.elsereno/vault.v1.bin. Real JCS audit
  canonicalisation. Scanner CircuitBreaker + TemporalDedupe (5 min).
  Censys v2 client. Progress bars. Outbox worker with dead-letter.
  Retention with keep-if-referenced. Web server scaffold with full
  timeouts + CSRF HKDF. banner plugin (first real Protocol).
  Integration test scaffold.
- 2026-04-19 — F2 — **F2 closed.** XOT (RFC 1613) and AT-modem
  plugins land: from-scratch wire parsers (header + X.25 PTI
  classifier for XOT; line-oriented state machine for AT with
  CR/LF tolerance, 64 KiB ceiling, +CME/+CMS error codes, CONNECT
  recognition). Vendor detection for Hayes / GSM (Siemens, Nokia,
  Sierra, MultiTech, Cinterion, Telit, u-blox, Quectel, Huawei) and
  EN 81-28 lifts (KONE, Otis, Schindler). Probe plugins + simulators
  (`simulators/xot/`, `simulators/atmodem/`). Proxy handlers: XOT
  pass-through; AT proxy drops the full write-ban set (ATD*, ATA,
  AT+CMGS, AT+CMGW, AT+CMSS, AT+CMGD, AT+CFUN, AT+CPWROFF, +++).
  ADR-027, ADR-028. `make ci` green end-to-end (seven fuzz targets,
  ~4 min wall-clock). F2 snapshot written. Repo is at the brief's
  F2 milestone — ready for `git push` to a private GitHub remote.
- 2026-04-19 — F3 — **F3 closed.** Proxy framework under
  `internal/proxy` (TCP listener, Accept loop, IdleTimeout-driven
  deadlines, graceful ctx-cancel shutdown, `Hook` interface with
  optional rewrite semantics, LoggingHook over SafeBytes). Modbus/TCP
  plugin: from-scratch wire parser (MBAP + PDU + FC classifier +
  exception helper + FC 43/14 Device ID decoder + 3 fuzz targets),
  Probe (FC 1 + opportunistic FC 43/14 vendor strings), and proxy
  that short-circuits every CategoryWrite / non-14 MEI / unknown FC
  with IllegalFunction — upstream never sees a write. Modbus
  simulator (`simulators/modbus/`) on Go, plus a pymodbus runtime
  pointer. Chaos helpers under `test/chaos/` (RandomDropReader,
  LatencyReader, FlipBitsWriter, EarlyCloser — build tag `chaos`).
  ADR-029, ADR-030. Integration test
  `test/integration/modbus_integration_test.go` end-to-end through
  the framework. `make ci` green (ten fuzz targets, ~9 min wall-clock
  with trivy DB refresh).
- 2026-04-19 — F4 — **F4 closed.** Eight new ICS plugins land in one
  pass, all with from-scratch wire parsers + probe + fuzz target +
  ADR + protocol doc:
  s7 (TPKT/COTP port 102), enip (EtherNet/IP CIP ListIdentity port
  44818), bacnet (BVLC Who-Is UDP/47808), dnp3 (IEEE 1815 link
  frame port 20000), iec104 (APCI TESTFR port 2404), hartip
  (session initiate port 5094), fox (Niagara Fox banner 1911/4911),
  atg (Veeder-Root I20100 port 10001). banner plugin grows a
  DetectVendor() helper with Moxa/Lantronix/Digi/NetBurner/KONE/
  Otis/Schindler/OpenSSH rules. 12 plugins total registered.
  Dashboard MVP at `/` (inline HTMX-ready HTML listing plugins) +
  JSON API at `/api/v1/{plugins,scoring,health}` with
  `{schema: "api:v1", data: …}` envelope. OpenAPI 3.1 spec at
  `docs/openapi.yaml`. Conpot honeypot added to
  `simulators/docker-compose.test.yml` with mapped ports for all 8
  new plugins. ADRs 031..038. A fuzz-found panic in enip ListIdentity
  parser (truncated body) was fixed with stricter bounds checks;
  corpus entry retained as regression guard. `make ci` green (18
  fuzz targets). REPL bindings + Bearer-auth on /api/v1 + full
  dashboard UI land in F4 chunk 2 / F5.
- 2026-04-19 — F5 — **Closed.** Offensive build behind `-tags offensive`.
  ADR-039 triple-confirm wrapper (build tag + --accept-writes +
  --confirm-target + HMAC-SHA256 token via HKDF
  `info="elsereno/offensive/confirm/v1"`). ADR-040 per-plugin proxy
  write-gating for the 7 F4 pass-through plugins plus atg/fox/bacnet.
  ADR-041 dial guard with unbypassable ≤3-digit hard block. ADR-042
  seccomp-bpf scaffold (Linux PR_SET_NO_NEW_PRIVS; BPF filters land
  with F6 subprocess integrations). `offensive/write/{modbus,s7,enip,
  bacnet}` writers with deterministic SHA-256 payload hashes.
  `offensive/dial/Validate` three-gate validator. `offensive/harvest`
  probers for Telnet / FTP / HTTP-Basic / SNMPv2c. `offensive/exploits`
  registry + 2 public-stable DoS modules (CVE-2015-5374 Siemens
  SIPROTEC, CVE-2019-10953 CIP ListIdentity). `internal/canary`
  webhook sender with optional HMAC signature.
  `internal/exec.CommandSpec.AllowAnyPath` bypass with mandatory
  BypassAuditor. Default build remains read-only end-to-end; no
  offensive code path is reachable without the build tag.
  `make ci` green on both build variants. CLI wiring for
  `elsereno write|exploit|harvest|dial` lands with the DB-backed
  audit writer in F6.
- 2026-04-20 — F6 — **Closed.** Reporting + release. Five new output
  sinks: CEF 0.1 + RFC 5424 syslog + JIRA Cloud REST v3 + GitHub
  Issues REST + generic HMAC-signed webhook. HTML report polish
  (dark-mode, per-protocol sections with count/max/avg, top-5
  factor histogram). OpenAPI 3.1 autogen: code-sourced
  `internal/web/openapi.Spec()` + live `/api/v1/openapi.yaml` +
  `elsereno api openapi` CLI. Offensive CLI verbs (`write|exploit|
  harvest|dial`) land behind `-tags offensive`; all four are
  operator-usable today (delivery wiring carries over to F7 with
  the DB-backed audit writer). `--vault-passphrase-file <0600
  path>` unblocks non-interactive startup; mode + symlink + empty-
  file validation. 13 operator docs (`docs/protocols/*.md` + README
  + RELEASING.md). Dashboard polish with dark-mode palette, plugin
  grouping default vs offensive, scoring sidebar, severity chips.
  `.goreleaser.yml` migrated to v2 archives.ids; dry-run validated
  8 binaries × SBOM × SHA-256 checksums. F7 open carry-overs:
  dockers_v2 migration, offensive network delivery, seccomp-bpf
  filter sequences, SSE + findings/triage/runs DB panels.
- 2026-04-20 — F7 — **Closed.** Hardening + 1.0. Dockers_v2 migration +
  nightly per-target fuzz matrix. Regression benchmarks with benchstat
  CI comment. OpenTelemetry tracing scaffold + scanner spans. 6 STRIDE
  threat-model docs under `.context/threat-model/` (vault-audit, web,
  scanner-proxy, exec-scope, offensive, telemetry-canary). Supply-
  chain automation: OpenSSF Scorecard nightly, SLSA L3 provenance on
  tag, dependency-review with licence deny-list, osv-scanner,
  licenses-audit artefact. `internal/backup`: AES-256-GCM + two-stage
  HKDF + tar/gzip payload + 10 unit tests. `elsereno backup
  create|restore|inspect` CLI verbs honouring
  --vault-passphrase-file. Pentest dashboard panel at /admin/security
  showing 11 in-process controls + threat-model links + external
  sec-suite references. `scripts/release-gate.sh` + `make release-
  gate` + RELEASING.md 1.0 section. `SUPPLY-CHAIN.md` documents SLSA
  mapping + dep policy + SBOM diff recipe + secrets rotation table.
  Feature-complete for v1.0.0; tag is an operator task.
- 2026-04-20 — **Release v1.0.0** pushed to private repo
  RobinR00T/elSereno. 12 release assets: 5 archives (darwin/linux
  × amd64/arm64 + sqlite linux-amd64) + 6 CycloneDX SBOMs +
  cosign-signed checksums. Tag signed with GPG
  ACE3B86BACACE7D6. Known issues: `.intoto.jsonl` SLSA provenance
  missing (v2.0.0 generator finaliser bug; v1.0.1 fixes via
  v2.1.0), cosign `.sig` without `.bundle` (v1.0.1 adds bundle),
  GHCR image disabled (v1.1 carry-over).
- 2026-04-21 — **Release v1.0.1 polish** queued on main: cosign
  `--bundle`, SLSA generator bumped v2.0.0 → v2.1.0, pandoc
  pinned to upstream 3.9.0.2 .deb for determinism, README
  badges + signed-install recipe. Source code unchanged; config
  + docs only.
- 2026-04-21 — **v1.0.1** released. checksums.txt.bundle
  shipped; end-to-end cosign-verify-blob confirmed. SLSA
  `final` step still fails upstream (wrapped non-blocking in
  release.yml); `.intoto.jsonl` not on release yet.
- 2026-04-21 — **v1.1 chunks 1-3** landed on main: per-plugin
  offensive WriteGatedHandler (modbus/s7/enip full + 6 session
  primitives), file-backed audit writer + confirm adapter,
  network delivery wiring for `write modbus send` / `exploit
  run` / `audit verify-file`. 4 chunks pending: SSE + DB
  panels, GHCR image, BPF filters, OPC UA, wardialing batch.
- 2026-04-21 — **v1.1 chunk 4 (SSE half)** landed on main: new
  `internal/web/stream` package with channel-per-subscriber
  Broadcaster (slow-subscriber-dropped fan-out), `/api/v1/stream`
  SSE handler with retry + keepalive, dashboard live-feed panel
  (EventSource, CSP-nonce script), audit.Observer hook +
  `TailAudit` cross-process file tailer so offensive verbs in
  separate processes light up the dashboard. OpenAPI spec +
  `docs/openapi.yaml` snapshot include `/api/v1/stream`. DB
  tables + findings/triage/runs panels carry over into v1.2
  alongside the DB-backed audit Writer.
- 2026-04-21 — **v1.1 chunk 5 (GHCR docker image)** landed on
  main: `.goreleaser.yml` `dockers_v2` block with `sbom: true`
  (CycloneDX attestation) + `--attest=type=provenance,mode=max`,
  multi-arch (linux/amd64 + linux/arm64) under
  `ghcr.io/robinr00t/elsereno:<tag>` + `:latest`, cosign keyless
  `docker_signs` on the manifest. `.github/workflows/release.yml`
  adds `docker/setup-qemu-action@v3` + `docker/setup-buildx-action@v3`
  so the multi-arch + attestation pipeline works end-to-end.
  `Dockerfile` + `Dockerfile.sqlite` pin Go 1.25.4 (matching
  go.mod) on Alpine 3.22 / Debian bookworm. README + RELEASING
  documented with pull + cosign-verify recipes.
- 2026-04-21 — **v1.1 chunk 6 (seccomp-bpf sandbox)** landed on
  main: `offensive/sandbox/bpf_linux.go` compiles per-profile
  denylist BPF programs (prologue: LD arch / JEQ / LD nr;
  body: one JEQ per blocked syscall; tail: RET ALLOW / RET
  ERRNO|EPERM). `syscalls_linux.go` ships syscall-number tables
  for x86_64 + aarch64 (generic ABI, zero-entries dropped so
  unsupported syscalls don't accidentally match `read` at nr=0).
  `sandbox.Load` installs via `seccomp(SECCOMP_SET_MODE_FILTER,
  TSYNC)` so the filter covers every goroutine-backing thread.
  `offensiveRuntime.ApplySandbox` records an `offensive_sandbox`
  audit entry (new `audit.EventOffSandbox` + migration 00002)
  capturing profile + availability + kind. Wired into `write
  modbus send`, `exploit run`, and `harvest *` so they install
  the profile before any network I/O. Integration tests under
  the `sandbox_integration` build tag fork a child + verify
  ptrace (exploit) and socket (dial) return EPERM on native
  Linux. Legacy top-level `migrations/` dir removed — the
  `internal/db/migrations/` embed is the single source of truth.
