---
phase: F0
status: closed
last-updated: 2026-04-19
token-budget: 300
---

# Current state

**Phase**: F0 — Scaffolding
**Last closed**: **F0 on 2026-04-19**. `make ci` green end-to-end on
  the operator's machine: lint (golangci-lint v2.11.4, 0 issues), build
  (default + offensive + sqlite), test-race + test-cover, test-fuzz
  (smoke), sec (gosec + govulncheck + trivy + go-licenses + gitleaks,
  0 findings each), context-check.
**In progress**: nothing. Awaiting operator validation to open F1.
**Next**: F1 — inputs (Shodan/Censys/nmap XML/list/stdin), scanner,
  scoring engine v1, triage, outputs (NDJSON/CSV/HTML minimal),
  Prometheus populated + label sanitiser, retention keep-if-referenced,
  outbox with dead letter, IPv6 integration tests.
**Blockers**: none.

## Open questions
(none)
