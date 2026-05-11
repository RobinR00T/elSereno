#!/usr/bin/env bash
# start.sh — one-shot bring-up of the full ElSereno dev stack.
#
# Orchestrates:
#   1. Docker daemon check.
#   2. dev-db (Postgres 16 + migrations) via scripts/dev-db.sh up.
#   3. Build of ./elsereno + ./bin/elsereno if source is newer.
#   4. Vault init (interactive prompt if missing).
#   5. Load DATABASE_URL.
#   6. Run `elsereno serve --scan-store=db` (foreground or background).
#
# Usage:
#   scripts/start.sh                # foreground serve (Ctrl+C to stop)
#   scripts/start.sh --background   # serve in background; logs to /tmp
#   scripts/start.sh --no-serve     # everything except the serve step
#   scripts/start.sh --reset-db     # wipe + re-migrate the dev-db
#   scripts/start.sh --help
#
# Env overrides:
#   ELSERENO_PORT           # default 8787
#   ELSERENO_PASSPHRASE     # path to passphrase file (default ~/.elsereno/dev.pp)
#   SKIP_BUILD=1            # skip the rebuild step
#
# Idempotent: re-runs are cheap. Designed to be the everyday
# "I want to work on elsereno" command.
#
# Exit codes:
#   0  serve started successfully (or --no-serve completed)
#   1  pre-flight failure (Docker not running, no deps, etc.)
#   2  serve failed health check within timeout

set -euo pipefail

# ---- styling ----
G='\033[0;32m'; Y='\033[1;33m'; R='\033[0;31m'; B='\033[1m'; D='\033[0;36m'; N='\033[0m'
info() { printf "${G}▶${N} %s\n" "$*"; }
warn() { printf "${Y}⚠${N}  %s\n" "$*"; }
err()  { printf "${R}✗${N} %s\n" "$*" >&2; exit 1; }
hdr()  { printf "\n${B}${D}━━━ %s ━━━${N}\n" "$*"; }
ask()  { local a; printf "${B}? %s [y/N]: ${N}" "$*"; read -r a </dev/tty; [[ "$a" =~ ^[YySs] ]]; }

# ---- args ----
MODE_SERVE="foreground"   # foreground | background | none
RESET_DB=0
for arg in "$@"; do
    case "$arg" in
        --background)  MODE_SERVE="background" ;;
        --no-serve)    MODE_SERVE="none" ;;
        --reset-db)    RESET_DB=1 ;;
        --help|-h)
            grep -E '^# ' "$0" | sed 's/^# \?//' | head -30
            exit 0
            ;;
        *) err "unknown flag: $arg (try --help)" ;;
    esac
done

# ---- locate repo root ----
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || err "cannot cd to $ROOT"

# ---- env defaults ----
ELSERENO_PORT="${ELSERENO_PORT:-8787}"
ELSERENO_PASSPHRASE="${ELSERENO_PASSPHRASE:-${HOME}/.elsereno/dev.pp}"
SKIP_BUILD="${SKIP_BUILD:-0}"
SERVE_LOG="/tmp/elsereno-serve.log"

# ====================================================================
hdr "1/6 — Pre-flight"
# ====================================================================
command -v docker >/dev/null 2>&1 || err "docker not installed. Run scripts/bootstrap.sh first."
command -v go >/dev/null 2>&1     || err "go not installed. Run scripts/bootstrap.sh first."
docker info >/dev/null 2>&1       || err "Docker daemon not responding. Start Docker Desktop or 'sudo systemctl start docker'."
[ -f docker-compose.dev.yml ]     || err "docker-compose.dev.yml missing — not in repo root?"
info "Docker $(docker --version | awk '{print $3}' | tr -d ',') · Go $(go version | awk '{print $3}')"

# ====================================================================
hdr "2/6 — Bring up dev-db (Postgres 16)"
# ====================================================================
if [ "$RESET_DB" -eq 1 ]; then
    warn "Reset requested — will wipe Postgres volume."
    if ask "Confirm: this destroys all dev DB data."; then
        scripts/dev-db.sh reset
    else
        info "Reset cancelled — continuing with existing volume"
        scripts/dev-db.sh up
    fi
else
    scripts/dev-db.sh up
fi

# ====================================================================
hdr "3/6 — Build elsereno (if source newer than binary)"
# ====================================================================
need_build() {
    [ "$SKIP_BUILD" -eq 1 ] && return 1
    [ ! -x ./elsereno ] && return 0
    # If any .go file under ./cmd or ./internal is newer than the
    # binary, rebuild. find -newer is portable across BSD/GNU.
    [ -n "$(find ./cmd ./internal -name '*.go' -newer ./elsereno -print -quit 2>/dev/null)" ]
}

if need_build; then
    info "Rebuilding from HEAD ($(git describe --tags 2>/dev/null || echo 'no-tag'))..."
    mkdir -p bin
    go build -trimpath -o ./elsereno ./cmd/elsereno
    cp ./elsereno ./bin/elsereno
    info "Built: $(stat -f '%Sm' ./elsereno 2>/dev/null || stat -c '%y' ./elsereno)"
else
    info "Binary up-to-date: $(stat -f '%Sm' ./elsereno 2>/dev/null || stat -c '%y' ./elsereno)"
fi

# ====================================================================
hdr "4/6 — Vault status"
# ====================================================================
VAULT_DIR="${HOME}/.elsereno"
mkdir -p "$VAULT_DIR"

if [ ! -f "$ELSERENO_PASSPHRASE" ]; then
    warn "No passphrase file at $ELSERENO_PASSPHRASE"
    echo "    The dev workflow uses a passphrase file (0600) so serve can"
    echo "    auto-unlock without prompting. Production should use the"
    echo "    interactive vault unlock instead (PITF-032)."
    if ask "Create a random dev passphrase at $ELSERENO_PASSPHRASE?"; then
        umask 077
        # 16 bytes of crypto/rand → base64 (~22 chars).
        openssl rand -base64 16 > "$ELSERENO_PASSPHRASE"
        chmod 600 "$ELSERENO_PASSPHRASE"
        info "Created $ELSERENO_PASSPHRASE"
    else
        err "Cannot continue without a passphrase. Run './elsereno vault init' manually."
    fi
fi

# Verify vault state. `vault status` reports "initialised"
# or "not initialised" via stdout + exit-code 0 (per its
# Cobra spec). It takes no flags beyond --help.
VAULT_STATUS_OUT=$(./elsereno vault status 2>&1 || true)
case "$VAULT_STATUS_OUT" in
    *"initialised"*)
        info "Vault initialised — $VAULT_STATUS_OUT"
        ;;
    *)
        warn "Vault not initialised: $VAULT_STATUS_OUT"
        if ask "Run 'elsereno vault init' now (using $ELSERENO_PASSPHRASE)?"; then
            ./elsereno vault init --vault-passphrase-file "$ELSERENO_PASSPHRASE"
        else
            warn "Vault not initialised — serve will fail. To init later:"
            echo "    ./elsereno vault init --vault-passphrase-file $ELSERENO_PASSPHRASE"
        fi
        ;;
esac

# ====================================================================
hdr "5/6 — Load DATABASE_URL"
# ====================================================================
if [ -f "$VAULT_DIR/dev-db.env" ]; then
    # shellcheck disable=SC1091
    set -a; . "$VAULT_DIR/dev-db.env"; set +a
    info "DATABASE_URL = $DATABASE_URL"
else
    warn "dev-db.env not found — scripts/dev-db.sh should have created it"
fi

# ====================================================================
hdr "6/6 — Start serve"
# ====================================================================
case "$MODE_SERVE" in
    none)
        info "Skipping serve (--no-serve)"
        echo
        echo "To start manually:"
        echo "    ./elsereno serve --scan-store=db --vault-passphrase-file $ELSERENO_PASSPHRASE"
        echo
        info "✅ Dev stack ready"
        exit 0
        ;;
    background)
        info "Starting serve in background → $SERVE_LOG"
        ./elsereno serve --scan-store=db --vault-passphrase-file "$ELSERENO_PASSPHRASE" \
            >"$SERVE_LOG" 2>&1 &
        SERVE_PID=$!
        echo "    PID = $SERVE_PID"
        # Wait up to 10s for /healthz (loop var unused — _).
        for _ in 1 2 3 4 5 6 7 8 9 10; do
            sleep 1
            if curl -sf "http://127.0.0.1:${ELSERENO_PORT}/healthz" >/dev/null 2>&1; then
                info "/healthz OK"
                echo
                info "✅ Dev stack up · dashboard: http://127.0.0.1:${ELSERENO_PORT}"
                echo "    logs: tail -f $SERVE_LOG"
                echo "    stop: kill $SERVE_PID  (or: pkill -TERM -f 'elsereno serve')"
                exit 0
            fi
        done
        warn "/healthz did not respond within 10s — check $SERVE_LOG"
        tail -30 "$SERVE_LOG" || true
        exit 2
        ;;
    foreground)
        echo
        info "✅ Dev stack ready · starting serve in foreground"
        echo "    dashboard will be at http://127.0.0.1:${ELSERENO_PORT}"
        echo "    Ctrl+C to stop"
        echo
        exec ./elsereno serve --scan-store=db --vault-passphrase-file "$ELSERENO_PASSPHRASE"
        ;;
esac
