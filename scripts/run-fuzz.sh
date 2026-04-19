#!/usr/bin/env bash
# Discover all Fuzz* test functions in the repo and run each for $DURATION.
set -euo pipefail

DURATION="${1:-30s}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

any=0
while read -r pkg target; do
  [ -z "${target:-}" ] && continue
  echo ">>> fuzz $pkg $target ($DURATION)"
  any=1
  go test -run=^$ -fuzz="^${target}$" -fuzztime="$DURATION" "$pkg"
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
