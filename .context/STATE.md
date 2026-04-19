---
phase: F5
status: closed
last-updated: 2026-04-19
token-budget: 300
---

# Current state

**Phase**: F5 — Offensive build.
**Last closed**: **F5 on 2026-04-19**. `make ci` green end-to-end.
  See `.context/snapshots/f5-offensive.md`.
**In progress**: nothing. Awaiting validation to open F6 (reporting +
  release).
**Next**: F6 — reporting (HTML pulido, CEF/Syslog/JIRA/GitHub Issues),
  OpenAPI autogen, webhooks from outbox, dashboard polish + vault UI,
  docs/protocols/*, signed 0.1.0 release, repo público.
**Blockers**: none. F5 carry-overs:
  - CLI wiring for `elsereno write|exploit|harvest|dial` behind
    `-tags offensive` lands when the DB-backed audit writer ships
    in F6.
  - seccomp-bpf BPF-filter instruction sequences (F5 ships the
    profile scaffolding + PR_SET_NO_NEW_PRIVS; filters land with
    the subprocess integrations).

## Open questions
(none)
