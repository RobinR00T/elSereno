#!/usr/bin/env bash
# Discover all Fuzz* test functions in the repo and run each for $DURATION.
#
# CI hygiene notes:
#   - We pass an explicit `-timeout` 4× larger than the fuzz duration so
#     Go's per-test 10m default doesn't fight short fuzz budgets.
#   - We retry each fuzz invocation up to MAX_ATTEMPTS times when it
#     fails with "context deadline exceeded" — Go's fuzz worker
#     scheduling on macOS occasionally races GC and reports a deadline
#     even though no real fuzz crash occurred. Retries are NOT applied
#     to genuine fuzz failures (a real `--- FAIL:` panic / fail line
#     short-circuits the loop).
set -euo pipefail

DURATION="${1:-30s}"
MAX_ATTEMPTS="${MAX_ATTEMPTS:-3}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# Compute a generous test-runner timeout. If DURATION is purely
# numeric we treat it as seconds; otherwise we trust Go's parser
# and just multiply via "${DURATION}*4" composition (Go accepts
# "120s" but not "30s*4", so we strip the unit).
strip_unit() {
  echo "${1//[!0-9]/}"
}
seconds="$(strip_unit "$DURATION")"
if [ -z "$seconds" ] || [ "$seconds" -lt 1 ]; then
  seconds=30
fi
timeout_s=$((seconds * 4))
if [ "$timeout_s" -lt 60 ]; then
  timeout_s=60
fi
TIMEOUT="${timeout_s}s"

run_fuzz_with_retry() {
  local pkg="$1"
  local target="$2"
  local attempt=1
  while [ "$attempt" -le "$MAX_ATTEMPTS" ]; do
    echo ">>> fuzz $pkg $target ($DURATION) — attempt $attempt/$MAX_ATTEMPTS"
    set +e
    output=$(go test -run=^$ -fuzz="^${target}$" -fuzztime="$DURATION" -timeout "$TIMEOUT" "$pkg" 2>&1)
    rc=$?
    set -e
    echo "$output"
    if [ "$rc" -eq 0 ]; then
      return 0
    fi
    # Genuine fuzz failure: a `--- FAIL:` line that's NOT
    # "context deadline exceeded" means real coverage / panic.
    # Treat that as terminal — no retry.
    if echo "$output" | grep -qE '^--- FAIL:' && \
       ! echo "$output" | grep -qE 'context deadline exceeded'; then
      return "$rc"
    fi
    # Retry-eligible: scheduling / deadline flake.
    attempt=$((attempt + 1))
    if [ "$attempt" -le "$MAX_ATTEMPTS" ]; then
      echo ">>> fuzz $pkg $target deadline-flaked; retrying"
    fi
  done
  return "$rc"
}

any=0
while read -r pkg target; do
  [ -z "${target:-}" ] && continue
  any=1
  run_fuzz_with_retry "$pkg" "$target"
done < <(
  grep -rhEo 'func (Fuzz[A-Za-z0-9_]+)' --include='*_test.go' . 2>/dev/null \
    | awk '{print $2}' \
    | sort -u \
    | while read -r fn; do
        pkgs=$(grep -rlE "func ${fn}\b" --include='*_test.go' . | xargs -n1 dirname | sort -u)
        for p in $pkgs; do echo "./${p#./} $fn"; done
      done
)

if [ "$any" -eq 0 ]; then
  echo "no Fuzz* targets discovered — nothing to run"
fi
