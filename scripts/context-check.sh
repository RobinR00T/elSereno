#!/usr/bin/env bash
# Validate the .context/ tree:
#   - front-matter YAML present in every .md
#   - file size under 250 lines (except pitfalls.md and decisions/)
#   - pitfalls.md has at least 36 entries (H2 starting with "## PITF-")
#   - no document references a prior version of itself (PITF-007 / PITF-029)
#
# The detector is self-aware: it skips pitfalls.md (where the patterns are
# defined) and ignores code fences (PITF-036).

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

ERR=0

fail() { echo "::error::$*" >&2; ERR=1; }

# 1. Every .context/*.md has a YAML front-matter (--- ... ---) or is in
#    templates/pitfall.md (a fragment inserted into pitfalls.md verbatim).
while IFS= read -r -d '' f; do
  case "$f" in
    *.context/templates/pitfall.md) continue ;;  # fragment; no front-matter
  esac
  head -1 "$f" | grep -q '^---$' || fail "missing front-matter: $f"
done < <(find .context -type f -name '*.md' -print0)

# 2. Size limit for canonical context docs (not pitfalls, not decisions, not
#    CHANGELOG which grows over time).
while IFS= read -r -d '' f; do
  lines=$(wc -l < "$f")
  if [ "$lines" -gt 250 ]; then
    fail "context file exceeds 250 lines ($lines): $f"
  fi
done < <(find .context -maxdepth 1 -type f -name '*.md' \
           ! -name 'pitfalls.md' ! -name 'CHANGELOG.md' -print0)

# 3. pitfalls.md has >= 36 entries.
if [ -f .context/pitfalls.md ]; then
  n=$(grep -c '^## PITF-' .context/pitfalls.md || true)
  if [ "${n:-0}" -lt 36 ]; then
    fail "pitfalls.md has only ${n:-0} entries (need >=36)"
  fi
else
  fail "missing .context/pitfalls.md"
fi

# 4. PITF-007 detector: no document references "previous versions".
#    Scans docs we ship in the repo; excludes pitfalls.md (definitions) and
#    ignores code fences (PITF-036).
TARGETS=()
for p in .context README.md CLAUDE.md CONTRIBUTING.md docs; do
  if [ -e "$p" ]; then
    TARGETS+=("$p")
  fi
done

while IFS= read -r -d '' f; do
  awk -v file="$f" '
    /^```/ { in_code = !in_code; next }
    !in_code && /(versión anterior|mantener del v[0-9]+|sección v[0-9]+ sin cambios|del v[0-9]+)/ {
      printf "VIOLATES PITF-007 — %s:%d: %s\n", file, NR, $0
      err = 1
    }
    END { if (err) exit 1 }
  ' "$f" || ERR=1
done < <(find "${TARGETS[@]}" -type f -name '*.md' ! -name 'pitfalls.md' -print0)

# 5. Templates directory present with expected files.
for t in pitfall protocol adr snapshot; do
  [ -f ".context/templates/${t}.md" ] || fail "missing .context/templates/${t}.md"
done

# 6. Decisions directory has 26 ADRs.
ndec=$(find .context/decisions -type f -name '*.md' | wc -l | tr -d ' ')
if [ "$ndec" -lt 26 ]; then
  fail ".context/decisions has only $ndec ADRs (need >=26)"
fi

if [ $ERR -ne 0 ]; then
  echo "context-check failed" >&2
  exit 1
fi

echo "context-check ok"
