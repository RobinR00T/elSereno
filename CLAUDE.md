# Claude workspace instructions for ElSereno

## Reading order (cargar en este orden al empezar cualquier tarea)
1. `.context/_quickref.md` (always)
2. `.context/STATE.md` (always)
3. `.context/conventions.md` (always)
4. `.context/pitfalls.md` (always, anti-patterns catalogue)
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
5. **Update `INSTALL.md` if the change affects:** install/upgrade/uninstall flow, per-platform feature matrix (Linux vs macOS), build variants (default/offensive/mini), systemd unit, packaging (deb/rpm/apk/OCI), or any CLI verb visible at install-doc level. If unchanged, the close-commit message must say "INSTALL.md unchanged", silent platform drift is the failure mode this rule prevents (v1.49 standing directive).
6. **Build BOTH macOS + Linux artefacts** (`goreleaser release --snapshot --skip=publish,docker` covers both via the matrix in `.goreleaser.yml`). Verify the Linux binary stays statically linked (`file dist/elsereno_*_linux_amd64` should say "statically linked"; `go tool nm` should NOT show libc.so symbols).
7. Run `make context-check`.
8. Run `make ci`.

## Conflict resolution
ADR > pitfalls > protocol doc > code comment.

## Phase discipline
No future-phase work without owner approval.

## Security discipline
- golangci-lint strict, gosec, govulncheck, gitleaks, race, per-package coverage mandatory.
- Writes to ICS require `-tags offensive`. Dial/SMS require `-tags offensive`; recording delivery intent (`--disposition delivery-requested`) requires `--dial-allowed` (PITF-098). No command dials hardware yet (vNext). Numbers ≤3 digits blocked hard. Wardialing batch is vNext.
- Sanitize target-controlled bytes via `internal/render.SafeBytes`.
- Sanitize target-controlled strings via `internal/telemetry.SafeField`.
- Postgres TLS required when not loopback (`database.tls_required`, enforced in `internal/db.New`; only the `db` commands open Postgres today).
- Randomness only from `crypto/rand`.
- Subprocess only via `internal/exec.SafeCommand` with `CommandSpec{Name, Flags, Positional}`; the `--` separator is inserted deterministically.
- Audit: tombstone purge preserves chain; compact inserts rebase marker and skips metadata entries (genesis/chain_rebase/purge_event). Design: `audit purge`/`compact`/`verify` are stubs that exit 69; `audit verify-file` is what runs.
- Findings: one INSERT per finding today (`internal/repo/runwriter.go`); pgx.CopyFrom batching (ADR-008) is designed, not built. Audit: one writer appends to `~/.elsereno/audit.jsonl`; the Postgres audit writer (`OpenDBWriter`) is not wired to any command.
- Cookie Secure=true with TLS; false on HTTP loopback with comment rationale (design: `serve` sets no cookies today, PITF-087).
- Token rotation bumps persisted `web_state.token_generation` with advisory lock; middleware caches generation TTL 5s (design; not built yet, PITF-087).
- CSRF key HKDF from vault master key (derived, nothing uses it yet); `serve` requires vault unlocked (use `vault init` + `vault unlock`).
- Vault master key in memguard (mlocked) inside the process that opened it; destroyed by `Vault.Lock` or process exit. No signal handler zeroizes it, and in the one-shot CLI `vault lock` is a no-op.
- Exit codes: 128+signum (SIGINT=130, SIGTERM=143), for the first signal on a clean completion and for the second-signal hard exit.
- Errors live in the emitting package (ErrChainBroken in `internal/audit/`, ErrUnknownConfigField in `internal/config/`, domain errors in `internal/core/`).
- Timestamps RFC3339 with up to 6 fractional digits (microseconds; Postgres TIMESTAMPTZ).
- Audit `event_type` enumerated CHECK; source of truth is SQL DDL.
- Before writing code: read `pitfalls.md`.
- **Never secrets via argv, herestring, OR plain env vars without rationale**. Env vars with secrets leak via `/proc/<pid>/environ` and `ps e` (PITF-032); prefer file with 0600 for persistent secrets; env only for CI/cron contexts with documented acceptance.
- Never auto-create critical state silently (PITF-021). `vault init` is explicit.
- Never assume external CLI behaviour without verification (PITF-008).
- Never duplicate enumerations without declaring source of truth (PITF-030).
- `make ci` local MUST be a superset of CI jobs that catch build/tag bitrot (PITF-031).
