#!/usr/bin/env bash
# Generate man pages.
#   - man1/5/7: via pandoc from Markdown sources in
#     man/src/man{1,5,7}/*.md.
#
# v1.13+ may switch man1 to cobra/doc autogeneration once the
# `gen-man` cobra command is wired; until then man1 is hand-
# authored alongside man5/7.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

mkdir -p man/man1 man/man5 man/man7

if ! command -v pandoc >/dev/null 2>&1; then
  echo "pandoc not found. Install with one of:" >&2
  echo "  brew install pandoc        # macOS" >&2
  echo "  apt-get install pandoc     # Debian/Ubuntu" >&2
  exit 1
fi

# man1 / man5 / man7 — pandoc from sources.
# Source files are named `<name>.<section>.md` (e.g.
# elsereno-scope.5.md). Output drops `.md` and keeps the name
# so the result is `<name>.<section>`. An earlier version
# appended `.${section}` on top of the source-embedded section
# number, producing bogus `.5.5` / `.7.7` filenames that made
# the release workflow fail with "git is in a dirty state".
for section in 1 5 7; do
  src_dir="man/src/man${section}"
  out_dir="man/man${section}"
  if [ -d "$src_dir" ]; then
    for src in "$src_dir"/*.md; do
      [ -e "$src" ] || continue
      base=$(basename "$src" .md)
      out="${out_dir}/${base}"
      pandoc -s -t man "$src" -o "$out"
      echo "generated $out"
    done
  fi
done

echo "man pages generated"
