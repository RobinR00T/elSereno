---
id: 012
title: SQLite build via CGO with SQLCipher, native arch only
status: accepted
date: 2026-04-19
phase: F0
---

# ADR-012: SQLite build via CGO with SQLCipher, native arch only

## Context
The portable backend (ADR-005) must encrypt at rest to be acceptable for
vault storage. Pure-Go SQLite implementations do not provide SQLCipher.

## Decision
- Build with `-tags sqlite` uses `github.com/mutecomm/go-sqlcipher/v4`
  (SQLCipher-backed, CGO).
- `CGO_ENABLED=1` required.
- The CI `build-sqlite` job builds **only `linux/amd64`**; goreleaser
  emits a SQLite variant only for the runner's native arch
  (PITF-006).
- `Dockerfile.sqlite` is a dual-stage image with `gcc`, `musl-dev`,
  `libsqlcipher-dev` in the builder stage; runtime on
  `gcr.io/distroless/base-nodebug-debian12:nonroot`.

## Consequences
### Positive
- Operator gets an encrypted portable DB without extra tooling.
- Default pure-Go build is untouched.

### Negative / trade-offs
- CGO cross-compile is painful; we publish only the runner-native arch
  for the SQLite variant.
- Distributions with different libc (musl vs glibc) require separate
  builds.

## Alternatives considered
- `mattn/go-sqlite3` + application-level encryption: weaker, doesn't use
  SQLCipher page-level crypto.
- Pure-Go SQLite (e.g. `modernc.org/sqlite`): no SQLCipher support, weaker
  encryption story.

## References
- PITF-006, PITF-011; `Dockerfile.sqlite`.
