# Developer setup

This document covers how to bring up a full ElSereno development
environment from a clean machine. If you only want to **install**
the released binary for production use, see [`INSTALL.md`](../INSTALL.md)
instead.

> The end-state of this guide: you have the repo cloned, all
> required toolchain dependencies installed, a local Postgres 16
> running in Docker with every migration applied, the elsereno
> binary built from `HEAD`, and the dashboard accessible at
> `http://127.0.0.1:8787`.

---

## TL;DR

```bash
git clone https://github.com/RobinR00T/elSereno.git
cd elSereno

# One-shot dependency installer (asks before installing each missing tool):
scripts/bootstrap.sh

# One-shot dev stack bring-up (Docker + DB + migrate + build + serve):
scripts/start.sh
```

Open <http://127.0.0.1:8787>. That's it.

If something fails, every script has `--help` and exits with a
distinct code per failure class. The rest of this document
explains the moving parts.

---

## Prerequisites at a glance

| Tool              | Required for          | Default install via                  |
|-------------------|-----------------------|--------------------------------------|
| **go** (≥ 1.25)   | building from source  | `brew install go` / `apt golang-go`  |
| **git**           | everything            | system PM                            |
| **docker**        | dev-db (Postgres)     | Docker Desktop (macOS) / `apt docker.io` (Linux) |
| **docker compose** v2 | dev-db            | bundled with Docker Desktop          |
| **jq**            | dev-db status checks  | system PM                            |
| **golangci-lint** | `make lint`           | system PM or `go install`            |
| **gosec**         | `make sec`            | `go install`                         |
| **govulncheck**   | `make sec`            | `go install`                         |
| **gh** (GitHub CLI) | release flow + auth | system PM                            |
| **gpg**           | signing release tags  | system PM                            |
| **gitleaks**      | pre-flight secret scan | system PM or `go install`           |
| **goreleaser**    | producing releases    | system PM or `go install`            |
| **syft**          | SBOM generation (release-time) | `brew` or upstream script   |
| **cosign**        | keyless signing (release-time) | `brew` or upstream installer |

The first three rows are **strictly required**; rows 4-7 are
required for the full CI gate (`make ci`); the rest are
recommended or release-only.

---

## `scripts/bootstrap.sh` — dependency installer

`bootstrap.sh` walks the table above and, for each missing
tool, asks whether to install it via the host package manager.
On macOS it uses Homebrew; on Linux it detects apt / dnf /
pacman / apk in that order. Tools not packaged for the host
fall back to `go install` (for Go-native tools) or print the
upstream install URL (cosign, syft on Linux).

### Modes

```bash
scripts/bootstrap.sh            # interactive: report + prompt to install each missing
scripts/bootstrap.sh --check    # report only, never install (CI-friendly probe)
scripts/bootstrap.sh --yes      # auto-install all missing (no prompts)
scripts/bootstrap.sh --help
```

### Exit codes

| Code | Meaning                                                    |
|------|------------------------------------------------------------|
| 0    | All required deps satisfied (or installed successfully)    |
| 1    | Unrecoverable error (unsupported OS, no PM found, etc.)    |
| 2    | A required dep is missing and user declined to install it  |

### Idempotency

Re-running is cheap: tools already present are reported `[ok]`
and skipped. Safe to wire into a CI step or a Makefile target.

### Privilege model

`bootstrap.sh` calls `sudo apt-get install ...` / `sudo dnf ...`
on Linux when the host PM requires it. macOS Homebrew does not
need `sudo`. Tools installed via `go install` end up in
`$GOBIN` (default `$HOME/go/bin`) — make sure that's on your
`PATH`.

---

## `scripts/start.sh` — full dev stack bring-up

`start.sh` is the everyday command. It orchestrates:

1. **Pre-flight** — Docker daemon responsive, repo root looks
   right, `go` + `docker` present.
2. **`scripts/dev-db.sh up`** — Postgres 16 in a container on
   `127.0.0.1:5433`, then `elsereno db migrate up` to apply every
   embedded migration (currently `00001` → `00012`).
3. **Build elsereno** — if any `.go` file under `cmd/` or
   `internal/` is newer than `./elsereno`, rebuild
   (`go build -trimpath -o ./elsereno ./cmd/elsereno`) and copy
   to `bin/elsereno` for the dev-db helper.
4. **Vault** — if `~/.elsereno/dev.pp` (the dev passphrase file)
   is missing, offer to create one with `openssl rand`. If the
   vault itself is not yet initialised, offer to run `elsereno
   vault init`.
5. **Load `DATABASE_URL`** — sources `~/.elsereno/dev-db.env`
   that `scripts/dev-db.sh` writes.
6. **Start serve** — `./elsereno serve --scan-store=db
   --vault-passphrase-file ~/.elsereno/dev.pp`.

### Modes

```bash
scripts/start.sh                # foreground serve (Ctrl+C to stop)
scripts/start.sh --background   # background serve, logs to /tmp/elsereno-serve.log
scripts/start.sh --no-serve     # do everything except step 6
scripts/start.sh --reset-db     # destroy + recreate the Postgres volume (asks first)
scripts/start.sh --help
```

### Env overrides

| Variable              | Default               | Effect                                   |
|-----------------------|-----------------------|------------------------------------------|
| `ELSERENO_PORT`       | `8787`                | health-check probe endpoint              |
| `ELSERENO_PASSPHRASE` | `~/.elsereno/dev.pp`  | passphrase file path                     |
| `SKIP_BUILD`          | `0`                   | set to `1` to skip the rebuild step      |

### Exit codes

| Code | Meaning                                                   |
|------|-----------------------------------------------------------|
| 0    | Serve started OK (or `--no-serve` completed cleanly)      |
| 1    | Pre-flight failure (Docker down, deps missing, etc.)      |
| 2    | Serve failed `/healthz` within 10s (background mode only) |

### Logs

* Foreground mode: serve logs to stdout (the terminal).
* Background mode: serve logs to `/tmp/elsereno-serve.log`. Tail
  with `tail -f /tmp/elsereno-serve.log`.
* dev-db logs: `docker compose -f docker-compose.dev.yml logs db`.

### Cleanup

```bash
# Stop serve (background mode):
pkill -TERM -f 'elsereno serve'

# Stop the dev-db container (keeps volume):
scripts/dev-db.sh down

# Nuke the dev-db volume too (loses all data):
scripts/dev-db.sh reset
```

---

## `scripts/dev-db.sh` — Postgres lifecycle (existing)

Predates `start.sh` and remains the authoritative way to bring
up just the database without the binary:

```bash
scripts/dev-db.sh up        # start + wait-healthy + migrate
scripts/dev-db.sh down      # stop, keep volume
scripts/dev-db.sh reset     # wipe volume + re-up + migrate
scripts/dev-db.sh status    # docker compose ps + pg_isready
scripts/dev-db.sh env       # print the `export DATABASE_URL=…` line
```

The default port is `127.0.0.1:5433` (loopback only).
Adminer (DB UI) is defined in `docker-compose.dev.yml` but not
started by default; bring it up with:

```bash
docker compose -f docker-compose.dev.yml up -d adminer
open http://127.0.0.1:8080
# System: PostgreSQL · Server: db · User: elsereno · DB: elsereno · (no password — dev trust auth)
```

---

## Secrets and the vault

* `~/.elsereno/dev.pp` is the **dev passphrase file** that
  `start.sh` creates with `openssl rand -base64 16` on first run.
  Mode `0600`.
* Never copy this file to production. The production workflow
  is interactive `elsereno vault unlock` per shell session, no
  passphrase file on disk.
* If you lose `dev.pp`, `rm -rf ~/.elsereno/vault.db` (or
  whichever path your vault lives at) and re-run `start.sh` to
  re-init from scratch — only the dev secrets are lost.

### Why a dev passphrase file is OK (and why prod is different)

PITF-032 forbids long-lived secrets in argv / env vars
(visible via `ps e` and `/proc/<pid>/environ`). A 0600 file
read by a single privileged process satisfies the rule. The
dev workflow trades some convenience for development speed; do
not replicate the file-on-disk pattern in production.

---

## Releasing (for maintainers)

The release flow is documented separately in
[`INSTALL.md`](../INSTALL.md) (the operator-facing install
methods) and `.context/protocols/release.md`. Short version:

```bash
git tag -s vX.Y.Z -m "vX.Y.Z — <one-line summary>"
git push origin main
git push origin vX.Y.Z
GITHUB_TOKEN=$(gh auth token) \
GITHUB_REPOSITORY=RobinR00T/elSereno \
  goreleaser release --clean --skip=sign,docker
```

`--skip=sign` because cosign keyless requires a browser
device-flow that doesn't fit a non-interactive run; tags
already carry GPG signatures. `--skip=docker` because the
Docker images pipeline depends on env vars that only exist
inside GitHub Actions. Both pipelines run in CI when billing
is restored.

---

## Common failures

| Symptom | Likely cause | Fix |
|---|---|---|
| `Docker daemon not responding` | Docker Desktop closed / `dockerd` not running | Start Docker Desktop or `sudo systemctl start docker` |
| `dev-db.sh: line N: /Users/Jane/AI projects/...: No such file or directory` | Outdated `dev-db.sh` (pre-`e007f13`) doesn't handle paths with spaces | Update repo: `git pull` and re-run |
| Migrations report `migrations applied` but `\dt` shows no new tables | Binary is **stale** — embedded migrations don't include the recent ones | `scripts/start.sh` rebuilds automatically; otherwise: `go build -o elsereno ./cmd/elsereno && ./elsereno db migrate up` |
| `serve` exits with `vault not initialised` | First-run; vault state missing | `./elsereno vault init --passphrase-file ~/.elsereno/dev.pp` |
| `gh auth status` shows token invalid after running hygiene flow | Bootstrap PAT was revoked; `gh` had it cached | `gh auth login -h github.com` (web flow recommended) |
| `goreleaser` fails with `GITHUB_REPOSITORY` template error | Env not set (only exists inside GitHub Actions) | Prepend `GITHUB_REPOSITORY=RobinR00T/elSereno` to the command |

---

## Reference layout

```
elSereno/
├── scripts/
│   ├── bootstrap.sh          # dependency installer (this doc, §1)
│   ├── start.sh              # full stack bring-up (§2)
│   ├── dev-db.sh             # Postgres lifecycle (§3)
│   ├── context-check.sh      # .context/STATE.md size guard
│   ├── release-gate.sh       # CI superset, called by `make release-gate`
│   ├── release-smoke.sh      # post-release sanity probe
│   ├── run-fuzz.sh           # fuzzing harness wrapper
│   ├── gen-manpages.sh       # man pages generator
│   └── install-hooks.sh      # git hooks installer
├── docs/
│   ├── DEV-SETUP.md          # ← you are here
│   ├── ARCHITECTURE.md
│   ├── manual/               # man pages source
│   ├── openapi.yaml          # API spec
│   └── protocols/            # per-protocol engineering notes
└── INSTALL.md                # operator-facing install (released binary)
```

---

## Further reading

* [`INSTALL.md`](../INSTALL.md) — for production install of the
  released binary (deb/rpm/apk/OCI/tarball).
* [`README.md`](../README.md) — feature overview + 30-second
  Quickstart.
* `.context/STATE.md` — current cycle state (internal).
* `.context/protocols/*.md` — per-area engineering notes.
* `.context/pitfalls.md` — anti-patterns catalogue (read before
  modifying production code).
