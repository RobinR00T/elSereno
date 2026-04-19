# Contributing to ElSereno

Thank you for your interest in ElSereno. The project is currently private
and in the scaffolding phase; external contributions will be opened after
Phase 6.

## First 15 minutes

1. Clone the repository and ensure Go 1.22+ and Docker are installed.
2. Start the dev database:

   ```sh
   docker compose -f docker-compose.dev.yml up -d
   ```

3. Run the setup:

   ```sh
   make tidy
   make build
   ./bin/elsereno doctor
   ./bin/elsereno init
   ./bin/elsereno vault init
   ./bin/elsereno vault unlock
   ./bin/elsereno db migrate up
   ```

4. Read these five files, in order, before editing anything:

   1. `.context/_quickref.md`
   2. `.context/STATE.md`
   3. `.context/conventions.md`
   4. `.context/pitfalls.md`
   5. `.context/protocols/<scope>.md` (only the protocol you are touching)

## Adding a new protocol

1. Create `internal/protocols/<name>/` with a `doc.go`, `wire/` parser,
   `probe.go`, `repl.go`, and (for proxy) `proxy.go`.
2. Implement `core.Protocol` and register via `init()` in
   `cmd/elsereno/plugins.go`.
3. Add `testdata/<name>/{benign,malicious}/` with golden files.
4. Write `FuzzXxx` fuzz tests for binary parsers.
5. Add `.context/protocols/<name>.md` using `templates/protocol.md`.
6. If a non-obvious design choice was needed, add an ADR via
   `templates/adr.md`.
7. If a new anti-pattern emerged, add an entry to `.context/pitfalls.md`
   using `templates/pitfall.md`.

## Commits and branches

- **Conventional Commits**. One logical change per commit.
- **Default branch**: `main`.
- **DCO sign-off required**: `git commit -s`.

## Local vs remote CI

`make ci` runs the same build variants (default / offensive / sqlite),
tests, fuzz smoke, and security scans as the CI pipeline, and is a
reasonable local approximation. **The remote CI is authoritative.** See
PITF-031 for why `make ci` is kept a functional superset of the bitrot-
catching CI jobs.

## Code review

All PRs require:

1. Green CI (lint, builds × 3, tests + race + coverage, fuzz smoke, sec,
   context, CodeQL).
2. Coverage thresholds (protocols 90 %, core 85 %, else 80 %).
3. `.context/pitfalls.md` reviewed against the change.
4. Updated `.context/STATE.md`, `.context/CHANGELOG.md` when the change
   closes a phase or a significant milestone.

## Security

See `SECURITY.md` for the disclosure policy and threat model.

## Legal

Contributions are licensed under the MIT License (see `LICENSE`). By
contributing you certify the Developer Certificate of Origin (DCO) per the
sign-off in your commits.
