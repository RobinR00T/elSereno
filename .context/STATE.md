---
phase: F4
status: closed
last-updated: 2026-04-19
token-budget: 300
---

# Current state

**Phase**: F4 — Remaining ICS plugins + dashboard + API.
**Last closed**: **F4 on 2026-04-19**. `make ci` green end-to-end.
  See `.context/snapshots/f4-ics-plugins-dashboard.md`.
**In progress**: nothing. Awaiting validation to open F5 (offensive
  build).
**Next**: F5 — offensive build (`-tags offensive`), writes /
  exploits / harvest / dial with triple confirm, per-plugin proxy
  write-gating matrices, seccomp-bpf sandbox on Linux (ADR-010
  supplementary), `--no-allowlist` bypass with audit trail,
  canary webhook.
**Blockers**: none.

## Open questions
(none)
