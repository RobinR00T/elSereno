---
phase: F1
status: in-progress
last-updated: 2026-04-19
token-budget: 300
---

# Current state

**Phase**: F1 — Inputs, scanner, scoring, triage, observability.
**Last closed**: **F0 on 2026-04-19**. `make ci` green end-to-end.
**In progress**: F1 chunks 1 and 2 landed. Adapters for inputs,
  scanner, scoring, triage, NDJSON/CSV/HTML outputs, Prometheus
  (populated + label sanitiser), vault (AES-GCM + Argon2id + HKDF +
  memguard), and goose-backed DB migrations are all in place and
  covered by race tests. `make ci` green. See
  `.context/snapshots/f1-inputs-scanner-observability.md`.
**Next**: F1 chunk 3 — wire CLI verbs (`db migrate/status/verify`,
  `vault init/unlock/lock/status`, `creds store/list/show/rotate/
  purge`, `token rotate/show`, `audit verify/purge/compact`) to the
  adapters above; Censys client; outbox worker with dead-letter;
  retention enforcement; progress bars with NO_COLOR; web server
  scaffold with full timeouts and the HKDF-derived CSRF key;
  docker-compose-backed integration suite to close F1.
**Blockers**: none.

## Open questions
(none)
