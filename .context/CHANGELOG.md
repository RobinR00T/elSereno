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
