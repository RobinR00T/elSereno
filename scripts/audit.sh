#!/usr/bin/env bash
# audit.sh — single-command proactive audit of the entire repo.
#
# Catches the failure classes we hit during the 2026-05-10/12
# sessions (and any new ones added over time) BEFORE they end
# up in an interactive session. Designed to be:
#
#   - Idempotent (re-runnable).
#   - macOS bash 3.2 compatible.
#   - Useful both interactively + as a CI gate.
#
# Usage:
#   scripts/audit.sh                # default = --full
#   scripts/audit.sh --quick        # YAML + docs + git state only (~5s)
#   scripts/audit.sh --full         # everything incl. make ci (~5 min)
#   scripts/audit.sh --ci           # full + GH Actions-friendly output
#   scripts/audit.sh --help
#
# Exit codes:
#   0  every check passed
#   1  at least one critical check failed
#   2  invocation error
#
# Companion docs:
#   docs/OPERATIONS.md §"Audit checklist"
#   memory/elsereno_operational_playbook.md (Claude side, off-repo)

set -uo pipefail   # NOT -e — we want to run all checks and aggregate

MODE="full"
for arg in "${@:-}"; do
    case "$arg" in
        --quick) MODE="quick" ;;
        --full)  MODE="full" ;;
        --ci)    MODE="ci" ;;
        --help|-h)
            grep -E '^# ' "$0" | sed 's/^# \?//' | head -30
            exit 0
            ;;
        "") ;;
        *) echo "unknown flag: $arg (try --help)" >&2; exit 2 ;;
    esac
done

# ---- styling (suppress colors in CI mode) ----
if [ "$MODE" = "ci" ]; then
    G=''; Y=''; R=''; B=''; D=''; N=''
else
    G='\033[0;32m'; Y='\033[1;33m'; R='\033[0;31m'; B='\033[1m'; D='\033[0;36m'; N='\033[0m'
fi

STATUS=0
N_PASS=0
N_FAIL=0
N_SKIP=0
FAILED_CHECKS=""

ok()   { printf "  ${G}✓${N} %s\n" "$*"; N_PASS=$((N_PASS+1)); }
fail() {
    printf "  ${R}✗${N} %s\n" "$*"
    if [ "$MODE" = "ci" ]; then
        printf "::error::audit fail: %s\n" "$*"
    fi
    N_FAIL=$((N_FAIL+1)); STATUS=1
    FAILED_CHECKS="$FAILED_CHECKS\n  - $*"
}
skip() { printf "  ${Y}—${N} %s (skipped)\n" "$*"; N_SKIP=$((N_SKIP+1)); }
hdr()  { printf "\n${B}${D}━━━ %s ━━━${N}\n" "$*"; }

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# ====================================================================
hdr "1. Git state"
# ====================================================================
if [ -z "$(git status --porcelain 2>/dev/null)" ]; then
    ok "Working tree clean"
else
    fail "Working tree dirty (uncommitted/untracked files)"
fi

if git fetch origin --quiet 2>&1 | tail -1 | grep -q error; then
    skip "Sync check (fetch failed — maybe offline)"
else
    if [ -z "$(git log --oneline origin/main..HEAD 2>/dev/null)" ] && \
       [ -z "$(git log --oneline HEAD..origin/main 2>/dev/null)" ]; then
        ok "Local main = origin/main"
    else
        fail "Local main diverged from origin/main (pull/push?)"
    fi
fi

# ====================================================================
hdr "2. YAML syntax (.github/* + docker-compose + openapi)"
# ====================================================================
YAML_VALIDATOR=""
if command -v ruby >/dev/null 2>&1; then
    YAML_VALIDATOR="ruby -ryaml -e 'YAML.safe_load(File.read(ARGV[0]), aliases: true)'"
elif command -v python3 >/dev/null 2>&1 && python3 -c "import yaml" 2>/dev/null; then
    YAML_VALIDATOR="python3 -c 'import sys,yaml; yaml.safe_load(open(sys.argv[1]))'"
elif command -v yq >/dev/null 2>&1; then
    YAML_VALIDATOR="yq eval '.' >/dev/null"
fi

if [ -z "$YAML_VALIDATOR" ]; then
    skip "No YAML validator available (install ruby / python+pyyaml / yq)"
else
    yamls=$(find .github -name '*.yml' -o -name '*.yaml' 2>/dev/null)
    [ -f docker-compose.dev.yml ] && yamls="$yamls docker-compose.dev.yml"
    [ -f docs/openapi.yaml ] && yamls="$yamls docs/openapi.yaml"
    [ -f .goreleaser.yml ] && yamls="$yamls .goreleaser.yml"

    YAML_FAIL=""
    for f in $yamls; do
        [ -f "$f" ] || continue
        if ! eval "$YAML_VALIDATOR" "$f" >/dev/null 2>&1; then
            YAML_FAIL="$YAML_FAIL $f"
        fi
    done
    if [ -z "$YAML_FAIL" ]; then
        ok "All YAML files valid ($(echo "$yamls" | wc -w | tr -d ' ') checked)"
    else
        fail "YAML syntax errors in:$YAML_FAIL"
    fi
fi

# ====================================================================
hdr "3. Dependabot config schema (no empty arrays)"
# ====================================================================
if [ -f .github/dependabot.yml ]; then
    # Schema-quirk we hit: `ignore: []` (and other empty arrays) trip
    # the validator. Detect any empty arrays at top-level keys.
    EMPTY_ARRAYS=$(grep -nE ':\s*\[\s*\]$' .github/dependabot.yml || true)
    if [ -z "$EMPTY_ARRAYS" ]; then
        ok "No empty arrays in dependabot.yml (schema: minItems: 1)"
    else
        fail "Empty arrays present (Dependabot rejects these):"
        echo "$EMPTY_ARRAYS" | sed 's/^/      /'
    fi
else
    skip "No .github/dependabot.yml found"
fi

# ====================================================================
hdr "4. Docs links (relative .md targets must exist)"
# ====================================================================
DOC_FAIL=""
for doc in $(find . -maxdepth 3 -name '*.md' -not -path './node_modules/*' -not -path './.git/*' 2>/dev/null); do
    grep -oE '\]\([^)]+\.md[^)]*\)' "$doc" | tr -d '()' | sed 's/^]//' | while IFS='' read -r ref; do
        ref=${ref%#*}; ref=${ref%% *}
        [ -z "$ref" ] && continue
        case "$ref" in
            http*) continue ;;
            /*) target="$ref" ;;
            *) target="$(dirname "$doc")/$ref" ;;
        esac
        # Resolve via cd:
        rdir=$(dirname "$target")
        rname=$(basename "$target")
        if [ -d "$rdir" ]; then
            abs="$(cd "$rdir" && pwd)/$rname"
            [ -f "$abs" ] || echo "BROKEN|$doc|$ref"
        else
            echo "BROKEN|$doc|$ref"
        fi
    done
done > /tmp/.audit-broken-links.$$ 2>&1 || true

BROKEN_LINKS=$(grep '^BROKEN' /tmp/.audit-broken-links.$$ 2>/dev/null || true)
rm -f /tmp/.audit-broken-links.$$
if [ -z "$BROKEN_LINKS" ]; then
    ok "All markdown internal links resolve"
else
    fail "Broken markdown links:"
    echo "$BROKEN_LINKS" | head -10 | sed 's/^BROKEN|/      /' | sed 's/|/ → /'
fi

# ====================================================================
hdr "5. Go toolchain + go.mod"
# ====================================================================
if command -v go >/dev/null 2>&1; then
    ok "Go available: $(go version | awk '{print $3}')"
    if grep -q "^toolchain" go.mod 2>/dev/null; then
        ok "go.mod has toolchain pin: $(grep '^toolchain' go.mod)"
    else
        fail "go.mod lacks 'toolchain' pin (CI/local may use vulnerable Go)"
    fi
else
    fail "Go not installed"
fi

if [ "$MODE" = "quick" ]; then
    # Skip expensive checks for --quick mode
    hdr "Summary (quick mode)"
    printf "  ${G}pass=%d${N} · ${R}fail=%d${N} · ${Y}skip=%d${N}\n" "$N_PASS" "$N_FAIL" "$N_SKIP"
    if [ "$STATUS" -eq 0 ]; then
        printf "\n${G}▶ AUDIT PASS${N} (quick mode)\n"
    else
        printf "\n${R}▶ AUDIT FAIL${N}\nFailed checks:${FAILED_CHECKS}\n"
    fi
    exit "$STATUS"
fi

# ====================================================================
hdr "6. Build (default + offensive + mini)"
# ====================================================================
if go build ./... >/tmp/.audit-build.$$ 2>&1; then ok "build default"; else fail "build default — see /tmp/.audit-build.$$"; fi
if go build -tags offensive ./... >/tmp/.audit-build-off.$$ 2>&1; then ok "build offensive"; else fail "build offensive — see /tmp/.audit-build-off.$$"; fi
if go build -tags mini ./... >/tmp/.audit-build-mini.$$ 2>&1; then ok "build mini"; else fail "build mini — see /tmp/.audit-build-mini.$$"; fi

# ====================================================================
hdr "7. golangci-lint"
# ====================================================================
if command -v golangci-lint >/dev/null 2>&1; then
    if golangci-lint run ./... >/tmp/.audit-lint.$$ 2>&1; then
        ok "golangci-lint: 0 issues"
    else
        fail "golangci-lint reported issues — see /tmp/.audit-lint.$$"
    fi
else
    skip "golangci-lint not installed (scripts/bootstrap.sh)"
fi

# ====================================================================
hdr "8. Tests + race detector"
# ====================================================================
if go test -race -count=1 -short ./... >/tmp/.audit-test.$$ 2>&1; then
    ok "go test -race -short: all packages pass"
else
    fail "tests failed — see /tmp/.audit-test.$$ (last 30 lines below)"
    tail -30 /tmp/.audit-test.$$ | sed 's/^/      /'
fi

# ====================================================================
hdr "9. gosec"
# ====================================================================
if command -v gosec >/dev/null 2>&1; then
    if gosec -quiet ./... >/tmp/.audit-gosec.$$ 2>&1; then
        ok "gosec: 0 issues"
    else
        # gosec returns non-zero when issues found; check output
        if grep -q "Issues : 0" /tmp/.audit-gosec.$$; then
            ok "gosec: 0 issues"
        else
            fail "gosec reported issues — see /tmp/.audit-gosec.$$"
        fi
    fi
else
    skip "gosec not installed"
fi

# ====================================================================
hdr "10. govulncheck"
# ====================================================================
if command -v govulncheck >/dev/null 2>&1; then
    GOVULN_OUT=$(govulncheck ./... 2>&1)
    if echo "$GOVULN_OUT" | grep -q "No vulnerabilities found"; then
        ok "govulncheck: No vulnerabilities found"
    else
        N_VULNS=$(echo "$GOVULN_OUT" | grep -cE "^Vulnerability #")
        fail "govulncheck: $N_VULNS vulnerabilities found"
        echo "$GOVULN_OUT" | grep -E "^Vulnerability|^  More info" | head -20 | sed 's/^/      /'
    fi
else
    skip "govulncheck not installed"
fi

# ====================================================================
hdr "11. context-check (STATE.md size + invariants)"
# ====================================================================
if [ -x scripts/context-check.sh ]; then
    if scripts/context-check.sh >/tmp/.audit-context.$$ 2>&1; then
        ok "context-check: OK"
    else
        fail "context-check failed — see /tmp/.audit-context.$$"
    fi
else
    skip "scripts/context-check.sh not present"
fi

# ====================================================================
hdr "12. Git tag signatures (last 3 tags)"
# ====================================================================
TAGS=$(git tag --list 'v*' --sort=-v:refname | head -3)
if [ -z "$TAGS" ]; then
    skip "No tags yet"
else
    UNSIGNED=""
    for t in $TAGS; do
        if ! git tag -v "$t" >/dev/null 2>&1; then
            UNSIGNED="$UNSIGNED $t"
        fi
    done
    if [ -z "$UNSIGNED" ]; then
        ok "Last 3 tags GPG-signed: $TAGS"
    else
        fail "Tags missing GPG signature:$UNSIGNED"
    fi
fi

# ====================================================================
hdr "13. GitHub repo state (requires gh)"
# ====================================================================
if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
    REPO_SLUG=$(gh repo view --json nameWithOwner -q .nameWithOwner 2>/dev/null || echo "")
    if [ -n "$REPO_SLUG" ]; then
        # Visibility
        VIS=$(gh repo view --json visibility -q .visibility 2>/dev/null)
        if [ "$VIS" = "PUBLIC" ] || [ "$VIS" = "PRIVATE" ]; then
            ok "Repo $REPO_SLUG: $VIS"
        else
            skip "Visibility check (unexpected: $VIS)"
        fi

        # Code Scanning
        CS=$(gh api "repos/$REPO_SLUG/code-scanning/default-setup" --jq '.state' 2>/dev/null || echo "")
        if [ "$CS" = "configured" ]; then
            ok "Code Scanning: configured"
        else
            fail "Code Scanning state=\"${CS:-not-found}\" (expected: configured)"
        fi

        # Workflow permissions
        WF_PERM=$(gh api "repos/$REPO_SLUG/actions/permissions/workflow" --jq '.default_workflow_permissions' 2>/dev/null || echo "")
        if [ "$WF_PERM" = "write" ]; then
            ok "Workflow permissions: write"
        elif [ "$WF_PERM" = "read" ]; then
            fail "Workflow permissions: read (expected write — release flow needs it)"
        else
            skip "Workflow permissions check (got: $WF_PERM)"
        fi

        # Open Dependabot PRs (status info only — not a fail)
        DEP_PRS=$(gh pr list --state open --author 'app/dependabot' --json number 2>/dev/null | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "?")
        printf "  ${B}i${N} Open Dependabot PRs: %s\n" "$DEP_PRS"
    else
        skip "gh authenticated but repo slug not detected (run inside repo)"
    fi
else
    skip "gh not installed or not authenticated"
fi

# ====================================================================
hdr "Summary"
# ====================================================================
TOTAL=$((N_PASS + N_FAIL + N_SKIP))
printf "  ${G}pass=%d${N} · ${R}fail=%d${N} · ${Y}skip=%d${N} · total=%d\n" \
    "$N_PASS" "$N_FAIL" "$N_SKIP" "$TOTAL"

# Cleanup tmp files unless failures (preserve logs for debug)
if [ "$STATUS" -eq 0 ]; then
    rm -f /tmp/.audit-*.$$ 2>/dev/null
    printf "\n${G}▶ AUDIT PASS${N} — repo en estado sano\n"
else
    printf "\n${R}▶ AUDIT FAIL${N}\nFailed checks:${FAILED_CHECKS}\n\n"
    printf "Logs preservados en /tmp/.audit-*.$$ para debug.\n"
fi

exit "$STATUS"
