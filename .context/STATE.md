---
phase: F1
status: in-progress
last-updated: 2026-04-19
token-budget: 300
---

# Current state

**Phase**: F1 — Inputs, scanner, scoring, triage, observability (in progress).
**Last closed**: **F0 on 2026-04-19**. `make ci` green end-to-end.
**In progress**: F1 chunk 1 landed (cobra rewire; koanf loader with
  unknown-field rejector; zerolog+redaction with UUID exclusion; pgx
  pool with TLS policy; goose migration runner stub; non-network inputs
  list/stdin/nmapxml; outputs NDJSON/CSV; scoring engine v1 with
  embedded YAML; `config show|lint` and `scoring show|example` real
  CLI verbs; doctor with Go/platform/CAP_NET_RAW or root/nmap/IPv6/disk
  checks; `make ci` green).
**Next**: F1 chunk 2 — Shodan + Censys HTTP clients with rate limiting;
  scanner (resolve A+AAAA+IDN, dedupe, rate limits, jitter, retries,
  circuit breaker, resume snapshots, temporal dedup 5min); triage
  grouping; HTML output; progress bars with NO_COLOR; Prometheus
  populated + label sanitiser; vault real (memguard + Argon2id +
  HKDF); retention keep-if-referenced; outbox with dead letter;
  IPv6 integration tests; pgx stdlib bridge to activate the goose
  migration runner.
**Blockers**: none.

## Open questions
(none)
