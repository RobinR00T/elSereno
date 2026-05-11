#!/usr/bin/env bash
# dev-db.sh — one-shot bring-up of the development Postgres
# (docker-compose.dev.yml) + migration apply.
#
# Usage:
#   scripts/dev-db.sh up      # start + wait-for-healthy + migrate (default)
#   scripts/dev-db.sh down    # stop, keep volume
#   scripts/dev-db.sh reset   # stop + wipe volume + re-up + migrate
#   scripts/dev-db.sh status  # ps + ping
#   scripts/dev-db.sh env     # print the DATABASE_URL export line
#
# The script writes an .env-shaped file at ~/.elsereno/dev-db.env
# with the DATABASE_URL for non-interactive consumers.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE="${ROOT}/docker-compose.dev.yml"
DB_HOST="${DB_HOST:-127.0.0.1}"
DB_PORT="${DB_PORT:-5433}"
DB_USER="${DB_USER:-elsereno}"
DB_NAME="${DB_NAME:-elsereno}"
DATABASE_URL="postgres://${DB_USER}@${DB_HOST}:${DB_PORT}/${DB_NAME}?sslmode=disable"
ENV_FILE="${HOME}/.elsereno/dev-db.env"

pass() { printf '  \033[32m[ok]\033[0m %s\n' "$1"; }
fail() { printf '  \033[31m[fail]\033[0m %s\n' "$1"; exit 1; }
note() { printf '  \033[34m[--]\033[0m %s\n' "$1"; }

need() { command -v "$1" >/dev/null 2>&1 || fail "missing: $1"; }

require_deps() {
    need docker
    if ! docker compose version >/dev/null 2>&1; then
        fail "docker compose v2 not available"
    fi
    if [ ! -f "$COMPOSE" ]; then
        fail "compose file missing: $COMPOSE"
    fi
}

write_env_file() {
    mkdir -p "$(dirname "$ENV_FILE")"
    umask 077
    printf 'DATABASE_URL=%s\n' "$DATABASE_URL" > "$ENV_FILE"
    pass "wrote $ENV_FILE (DATABASE_URL)"
}

wait_healthy() {
    local tries=30
    while [ "$tries" -gt 0 ]; do
        local status
        status=$(docker compose -f "$COMPOSE" ps db --format json 2>/dev/null \
            | jq -r '.[0].Health // empty' 2>/dev/null || true)
        if [ "$status" = "healthy" ]; then
            pass "db healthy"
            return 0
        fi
        # Fallback: direct pg_isready in the container
        if docker compose -f "$COMPOSE" exec -T db \
                pg_isready -U "$DB_USER" -d "$DB_NAME" >/dev/null 2>&1; then
            pass "db accepting connections"
            return 0
        fi
        sleep 1
        tries=$((tries - 1))
    done
    fail "db did not become healthy in 30s"
}

apply_migrations() {
    # Use an array so each token quotes independently — `$ROOT` may
    # contain spaces (e.g. "/Users/Daniel/AI projects/elsereno"),
    # and an unquoted `$bin` string would word-split on those spaces
    # and try to exec the path's first chunk as a command. (Found
    # in the wild: line 78 failed with "AI: No such file or
    # directory" when ROOT had a space.)
    local bin="${ROOT}/bin/elsereno"
    local -a cmd
    if [ -x "$bin" ]; then
        cmd=("$bin")
    else
        note "bin/elsereno not built — running via go run"
        cmd=(go run "${ROOT}/cmd/elsereno")
    fi
    pushd "$ROOT" >/dev/null
    if DATABASE_URL="$DATABASE_URL" "${cmd[@]}" db migrate up 2>&1 | tail -3; then
        pass "migrations applied"
    else
        fail "migrations failed — see output above"
    fi
    popd >/dev/null
}

cmd_up() {
    require_deps
    pushd "$ROOT" >/dev/null
    docker compose -f "$COMPOSE" up -d db
    popd >/dev/null
    wait_healthy
    write_env_file
    apply_migrations
    echo
    echo "  Next steps:"
    echo "    export \$(grep -v '^#' $ENV_FILE | xargs)"
    echo "    bin/elsereno serve --vault-passphrase-file ~/.elsereno/dev.pp"
    echo
    note "DATABASE_URL = ${DATABASE_URL}"
}

cmd_down() {
    require_deps
    pushd "$ROOT" >/dev/null
    docker compose -f "$COMPOSE" stop db
    popd >/dev/null
    pass "db stopped (volume kept)"
}

cmd_reset() {
    require_deps
    pushd "$ROOT" >/dev/null
    note "wiping volume — you will LOSE all data in the dev db"
    docker compose -f "$COMPOSE" down -v
    docker compose -f "$COMPOSE" up -d db
    popd >/dev/null
    wait_healthy
    write_env_file
    apply_migrations
}

cmd_status() {
    require_deps
    pushd "$ROOT" >/dev/null
    docker compose -f "$COMPOSE" ps db
    popd >/dev/null
    echo
    if docker exec elsereno-db-1 pg_isready -U "$DB_USER" -d "$DB_NAME" 2>/dev/null; then
        pass "pg_isready green on ${DB_HOST}:${DB_PORT}"
    else
        note "pg_isready red — not running or unreachable"
    fi
    echo
    if [ -f "$ENV_FILE" ]; then
        note "env file: $ENV_FILE"
    else
        note "env file missing — run 'scripts/dev-db.sh up' to create it"
    fi
}

cmd_env() {
    echo "export DATABASE_URL=\"${DATABASE_URL}\""
}

case "${1:-up}" in
    up)     cmd_up ;;
    down)   cmd_down ;;
    reset)  cmd_reset ;;
    status) cmd_status ;;
    env)    cmd_env ;;
    *)      fail "unknown command: $1 (expected: up|down|reset|status|env)" ;;
esac
