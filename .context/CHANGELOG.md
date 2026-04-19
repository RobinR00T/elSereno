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
