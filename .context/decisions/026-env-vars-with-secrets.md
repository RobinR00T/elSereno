---
id: 026
title: Env vars with secrets — warn, don't ban
status: accepted
date: 2026-04-19
phase: F0
---

# ADR-026: Env vars with secrets — warn, don't ban

## Context
`ELSERENO_VAULT_PASSPHRASE`, `SHODAN_API_KEY`, `CENSYS_API_ID`,
`CENSYS_API_SECRET`: all are secrets that are frequently set via env
vars. Env vars leak via `/proc/<pid>/environ` (readable by the same
user) and `ps e` (PITF-032). We cannot outright ban them because CI and
cron legitimately need a non-interactive transport.

## Decision
- Env vars with secrets are **allowed** for CI/cron.
- In contexts where `stderr` is a TTY, ElSereno emits a **warning** on
  startup recommending either an interactive prompt (`vault unlock`) or a
  0600 file.
- `.env.example`, `README.md`, and `CLAUDE.md` document the leakage
  surface.
- Argv and herestring transport of secrets remains **banned** (PITF-016).

## Consequences
### Positive
- Unattended automation still works.
- Interactive misuse is surfaced to the operator once per process start.

### Negative / trade-offs
- The warning may produce noise for operators who run in tmux with stdin
  not attached but a TTY stderr; we accept this.

## Alternatives considered
- Ban env vars for secrets: breaks CI, cron, container environments.
- Silently accept: same blind spot as today's field practice; no
  improvement.

## References
- PITF-016, PITF-032; `.env.example`; `README.md` target-acquisition
  section.
