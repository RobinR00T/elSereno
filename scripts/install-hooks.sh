#!/usr/bin/env bash
set -euo pipefail

if ! command -v lefthook >/dev/null; then
  echo "lefthook not found. Install with one of:" >&2
  echo "  go install github.com/evilmartians/lefthook@latest" >&2
  echo "  brew install lefthook          # macOS" >&2
  echo "  apt-get install lefthook       # Debian/Ubuntu (recent)" >&2
  echo "  or see https://github.com/evilmartians/lefthook#install" >&2
  exit 1
fi

lefthook install
echo "hooks installed"
