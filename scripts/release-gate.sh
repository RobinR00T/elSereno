#!/usr/bin/env bash
# release-gate validates every 1.0 precondition that does not
# depend on external state (GitHub, Sigstore, GHCR). Run this
# locally before `git tag -s` and in a CI gate before cutting the
# release workflow.
#
# Exit codes:
#   0  — all gates pass
#   1  — at least one gate failed; see stderr
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

status=0
ok()   { printf "  \033[32m[ok]\033[0m %s\n" "$*"; }
fail() { printf "  \033[31m[fail]\033[0m %s\n" "$*" >&2; status=1; }

say_section() { printf "\n== %s ==\n" "$*"; }

say_section "working tree"
if [ -n "$(git status --porcelain)" ]; then
  fail "working tree is dirty — commit or stash before tagging"
else
  ok "git status clean"
fi

say_section "tests + lint"
if go test ./... >/dev/null 2>&1; then
  ok "go test ./..."
else
  fail "go test failed — see \`make test\`"
fi

if go test -tags offensive ./... >/dev/null 2>&1; then
  ok "go test -tags offensive ./..."
else
  fail "go test -tags offensive failed"
fi

if golangci-lint run --timeout 3m ./... >/dev/null 2>&1; then
  ok "golangci-lint (default)"
else
  fail "golangci-lint (default) reported issues"
fi

if golangci-lint run --build-tags offensive --timeout 3m ./... >/dev/null 2>&1; then
  ok "golangci-lint (offensive)"
else
  fail "golangci-lint (offensive) reported issues"
fi

say_section "context"
if bash scripts/context-check.sh >/dev/null 2>&1; then
  ok "context-check"
else
  fail "scripts/context-check.sh failed"
fi

say_section "docs"
for f in README.md SECURITY.md LEGAL.md CONTRIBUTING.md CODE_OF_CONDUCT.md NON-GOALS.md CHANGELOG.md SUPPLY-CHAIN.md RELEASING.md TODO.md; do
  if [ -f "$f" ]; then
    ok "$f present"
  else
    fail "missing $f"
  fi
done

if [ -d docs/protocols ] && [ "$(ls -1 docs/protocols | wc -l)" -ge 12 ]; then
  ok "docs/protocols populated"
else
  fail "docs/protocols missing or incomplete"
fi

if [ -d .context/threat-model ] && [ -f .context/threat-model/README.md ]; then
  ok ".context/threat-model populated"
else
  fail ".context/threat-model missing"
fi

say_section "goreleaser"
if command -v goreleaser >/dev/null 2>&1; then
  if goreleaser build --snapshot --clean --id elsereno-default --id elsereno-offensive >/dev/null 2>&1; then
    ok "goreleaser snapshot build"
  else
    fail "goreleaser snapshot build failed"
  fi
else
  printf "  \033[33m[skip]\033[0m goreleaser not installed locally\n"
fi

say_section "sec suite"
if command -v govulncheck >/dev/null 2>&1; then
  if govulncheck ./... >/dev/null 2>&1; then
    ok "govulncheck"
  else
    fail "govulncheck reported CVEs"
  fi
else
  printf "  \033[33m[skip]\033[0m govulncheck not installed\n"
fi

if command -v gitleaks >/dev/null 2>&1; then
  if gitleaks detect --no-git --redact --exit-code 0 >/dev/null 2>&1; then
    ok "gitleaks"
  else
    fail "gitleaks reported leaks"
  fi
else
  printf "  \033[33m[skip]\033[0m gitleaks not installed\n"
fi

say_section "benchmarks"
if [ -f benchmarks/baseline.txt ]; then
  ok "benchmarks/baseline.txt checked in"
else
  fail "benchmarks/baseline.txt missing (run \`make bench-baseline\`)"
fi

say_section "summary"
if [ "$status" -eq 0 ]; then
  ok "release gate PASSED — safe to \`git tag -s\`"
else
  fail "release gate FAILED — see above"
fi
exit "$status"
