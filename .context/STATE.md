---
phase: F0
status: in-progress
last-updated: 2026-04-19
token-budget: 300
---

# Current state

**Phase**: F0 — Scaffolding
**Last closed**: (nothing)
**In progress**: Scaffolding landed. Structure, docs, CI config, Go
  skeleton (compilable, `go test ./...` green), migration DDL, and the
  context system are in place. See `.context/snapshots/f0-scaffolding.md`.
**Next**: install the tooling required for `make ci` (golangci-lint,
  gosec, govulncheck, trivy, gitleaks, go-licenses, pandoc, lefthook,
  docker), iterate `make ci` to green, then open F1 work.
**Blockers**: tooling installation on operator's machine (see snapshot
  "Debt accepted").

## Open questions
(none)
