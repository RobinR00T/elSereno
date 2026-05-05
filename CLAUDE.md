# Claude workspace instructions for ElSereno

## Reading order (cargar en este orden al empezar cualquier tarea)
1. `.context/_quickref.md` (always)
2. `.context/STATE.md` (always)
3. `.context/conventions.md` (always)
4. `.context/pitfalls.md` (always — anti-patterns catalogue)
5. Only `.context/protocols/<relevant>.md` for the protocol in scope.
6. Only `.context/decisions/<relevant>.md` if a design choice is involved.

## Never
- Load all protocol files at once.
- Mix files from different phases unless doing a cross-cutting change.
- Skip the test + lint cycle before marking a task done.
- Commit secrets, real third-party IPs, or real credentials (even in tests).
- Close a task without reviewing `pitfalls.md` against your change.
- Reference a prior version of any document; expand inline instead (PITF-007).

## After finishing a task
1. Update `.context/STATE.md`.
2. Update the specific `.context/protocols/<name>.md` or `.context/decisions/<id>.md`.
3. Add one-line entry to `.context/CHANGELOG.md`.
4. If a new anti-pattern was discovered, add entry to `.context/pitfalls.md` using `templates/pitfall.md` format.
5. **Update `INSTALL.md` if the change affects:** install/upgrade/uninstall flow, per-platform feature matrix (Linux vs macOS), build variants (default/offensive/mini), systemd unit, packaging (deb/rpm/apk/OCI), or any CLI verb visible at install-doc level. If unchanged, the close-commit message must say "INSTALL.md unchanged" — silent platform drift is the failure mode this rule prevents (v1.49 standing directive).
6. **Build BOTH macOS + Linux artefacts** (`goreleaser release --snapshot --skip=publish,docker` covers both via the matrix in `.goreleaser.yml`). Verify the Linux binary stays statically linked (`file dist/elsereno_*_linux_amd64` should say "statically linked"; `go tool nm` should NOT show libc.so symbols).
7. Run `make context-check`.
8. Run `make ci`.

## Conflict resolution
ADR > pitfalls > protocol doc > code comment.

## Phase discipline
No future-phase work without owner approval.

## Security discipline
- golangci-lint strict, gosec, govulncheck, gitleaks, race, per-package coverage mandatory.
- Writes to ICS require `-tags offensive`. Dial/SMS require `-tags offensive` + `--dial-allowed`. Numbers ≤3 digits blocked hard. Wardialing batch is vNext.
- Sanitize target-controlled bytes via `internal/render.SafeBytes`.
- Sanitize target-controlled strings via `internal/telemetry.SafeField`.
- Postgres TLS required when not loopback (`database.tls_required`).
- Randomness only from `crypto/rand`.
- Subprocess only via `internal/exec.SafeCommand` with `CommandSpec{Name, Flags, Positional}`; the `--` separator is inserted deterministically.
- Audit: tombstone purge preserves chain; compact inserts rebase marker and skips metadata entries (genesis/chain_rebase/purge_event).
- Findings via pgx.CopyFrom batched. Audit via sequential INSERT single-threaded.
- Cookie Secure=true with TLS; false on HTTP loopback with comment rationale.
- Token rotation bumps persisted `web_state.token_generation` with advisory lock; middleware caches generation TTL 5s.
- CSRF key HKDF from vault master key; `serve` requires vault unlocked (use `vault init` + `vault unlock`).
- Vault unlock-once cached in memguard; `vault lock` zeroizes; zeroized on SIGINT/SIGTERM.
- Exit codes: 128+signum (SIGINT=130, SIGTERM=143).
- Errors live in the emitting package (ErrChainBroken in `internal/audit/`, ErrUnknownConfigField in `internal/config/`, domain errors in `internal/core/`).
- Timestamps RFC3339 with up to 6 fractional digits (microseconds; Postgres TIMESTAMPTZ).
- Audit `event_type` enumerated CHECK; source of truth is SQL DDL.
- Before writing code: read `pitfalls.md`.
- **Never secrets via argv, herestring, OR plain env vars without rationale**. Env vars with secrets leak via `/proc/<pid>/environ` and `ps e` (PITF-032); prefer file with 0600 for persistent secrets; env only for CI/cron contexts with documented acceptance.
- Never auto-create critical state silently (PITF-021). `vault init` is explicit.
- Never assume external CLI behaviour without verification (PITF-008).
- Never duplicate enumerations without declaring source of truth (PITF-030).
- `make ci` local MUST be a superset of CI jobs that catch build/tag bitrot (PITF-031).
