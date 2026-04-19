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
