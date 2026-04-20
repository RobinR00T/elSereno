---
phase: F6
status: closed
last-updated: 2026-04-20
token-budget: 300
---

# Current state

**Phase**: F6 — Reporting + release.
**Last closed**: **F6 on 2026-04-20**. `make ci` green end-to-end.
  See `.context/snapshots/f6-reporting-release.md`.
**In progress**: nothing. Awaiting validation to open F7
  (hardening + 1.0).
**Next**: F7 — fuzz exhaustivo nightly, Gremlins mutation testing,
  STRIDE per module, pentest dashboard, supply-chain audit, OTel
  tracing production, encrypted backup automation, regression
  benchmarks in CI, release 1.0.0.
**Blockers**: none.

## F6 carry-overs
- `dockers:` → `dockers_v2:` (deprecation; current config still
  builds).
- `elsereno write|exploit|harvest|dial` network delivery wiring
  (dry-run only today; needs the DB-backed audit writer to emit
  `offensive_allowed` per ADR-039).
- seccomp-bpf BPF filter instruction sequences (NO_NEW_PRIVS +
  profile scaffold in place; filters land with the first
  offensive subprocess integration).
- SSE live feed on `/api/v1/stream`; findings / triage / runs
  DB tables + dashboard panels.

## Open questions
(none)
