#!/usr/bin/env bash
# bootstrap.sh — interactive dependency installer for ElSereno
# development workflow.
#
# Usage:
#   scripts/bootstrap.sh            # check + prompt to install missing
#   scripts/bootstrap.sh --check    # only report status, don't install
#   scripts/bootstrap.sh --yes      # auto-install missing (no prompts)
#   scripts/bootstrap.sh --help
#
# Covers macOS (Homebrew) and the common Linux distros (Debian/Ubuntu
# via apt, Fedora/RHEL via dnf, Arch via pacman, Alpine via apk).
# Tools not in the system package manager fall back to `go install`
# or a documented manual step (cosign / syft).
#
# Idempotent: re-runs are cheap (skipped if already installed).
#
# Required for build  : go, git
# Required for dev-db : docker, docker compose, jq
# Required for tests  : golangci-lint, gosec, govulncheck
# Recommended         : gh, gpg (tag signing), gitleaks
# Release-time        : goreleaser, syft, cosign
#
# Exit codes:
#   0  all required deps satisfied (or installed)
#   1  unrecoverable error (no supported package manager, etc.)
#   2  user declined to install a required dep

set -euo pipefail

# ---- styling ----
G='\033[0;32m'; Y='\033[1;33m'; R='\033[0;31m'; B='\033[1m'; D='\033[0;36m'; N='\033[0m'
ok()     { printf "  ${G}[ok]${N}    %s\n" "$*"; }
miss()   { printf "  ${Y}[miss]${N}  %s\n" "$*"; }
fail()   { printf "  ${R}[fail]${N}  %s\n" "$*"; }
note()   { printf "  ${D}[note]${N}  %s\n" "$*"; }
hdr()    { printf "\n${B}${D}━━━ %s ━━━${N}\n" "$*"; }
abort()  { printf "${R}✗${N} %s\n" "$*" >&2; exit 1; }

# ---- arg parsing ----
MODE="install"        # install | check
AUTO_YES=0
for arg in "$@"; do
    case "$arg" in
        --check)  MODE="check" ;;
        --yes|-y) AUTO_YES=1 ;;
        --help|-h)
            grep -E '^# ' "$0" | sed 's/^# \?//' | head -40
            exit 0
            ;;
        *) abort "unknown flag: $arg (try --help)" ;;
    esac
done

# ---- OS + package manager detection ----
OS=""
PM=""
case "$(uname -s)" in
    Darwin) OS="macos"; PM="brew" ;;
    Linux)
        OS="linux"
        if command -v apt-get >/dev/null 2>&1; then
            PM="apt"
        elif command -v dnf >/dev/null 2>&1; then
            PM="dnf"
        elif command -v pacman >/dev/null 2>&1; then
            PM="pacman"
        elif command -v apk >/dev/null 2>&1; then
            PM="apk"
        else
            PM="manual"
            note "no supported package manager found — install missing deps by hand"
        fi
        ;;
    *) abort "unsupported OS: $(uname -s)" ;;
esac
hdr "Environment"
ok "OS = $OS · package manager = $PM"

# ---- helpers ----

# ask_yes "prompt" → 0 if user answers y, 1 otherwise. Honors $AUTO_YES.
ask_yes() {
    local prompt="$1"
    if [ "$AUTO_YES" -eq 1 ]; then
        printf "  ${B}? %s${N} (auto-yes)\n" "$prompt"
        return 0
    fi
    local ans
    printf "  ${B}? %s [y/N]: ${N}" "$prompt"
    read -r ans </dev/tty
    [[ "$ans" =~ ^[YySs] ]]
}

# install_via_pm <pkg-name-by-manager...>
# Args: name in brew | name in apt | name in dnf | name in pacman | name in apk
# Empty string ("") means "not available via this manager".
install_via_pm() {
    local brew_n="${1:-}" apt_n="${2:-}" dnf_n="${3:-}" pacman_n="${4:-}" apk_n="${5:-}"
    case "$PM" in
        brew)
            [ -n "$brew_n" ] && brew install "$brew_n" && return 0
            return 1 ;;
        apt)
            [ -n "$apt_n" ] && sudo apt-get update -qq && sudo apt-get install -y "$apt_n" && return 0
            return 1 ;;
        dnf)
            [ -n "$dnf_n" ] && sudo dnf install -y "$dnf_n" && return 0
            return 1 ;;
        pacman)
            [ -n "$pacman_n" ] && sudo pacman -S --noconfirm "$pacman_n" && return 0
            return 1 ;;
        apk)
            [ -n "$apk_n" ] && sudo apk add "$apk_n" && return 0
            return 1 ;;
        manual)
            return 1 ;;
    esac
    return 1
}

# install_via_go <module-path>
# Falls back when system PM doesn't ship the tool.
install_via_go() {
    local mod="$1"
    command -v go >/dev/null 2>&1 || { fail "go not installed — cannot install $mod via go install"; return 1; }
    note "go install $mod@latest"
    GO111MODULE=on go install "$mod@latest"
}

# REQUIRED=1 means "abort if missing+declined"; REQUIRED=0 is informational.
# check_and_install <required> <name> <check-cmd> <install-fn-name>
check_and_install() {
    local required="$1" name="$2" check_cmd="$3" install_fn="$4"
    if eval "$check_cmd" >/dev/null 2>&1; then
        ok "$name"
        return 0
    fi
    miss "$name"
    if [ "$MODE" = "check" ]; then
        return 0  # report-only mode
    fi
    if ask_yes "install $name?"; then
        if "$install_fn"; then
            if eval "$check_cmd" >/dev/null 2>&1; then
                ok "$name (installed)"
                return 0
            else
                fail "$name install reported success but check still fails"
                [ "$required" -eq 1 ] && return 2
                return 0
            fi
        else
            fail "$name install failed"
            [ "$required" -eq 1 ] && return 2
            return 0
        fi
    else
        if [ "$required" -eq 1 ]; then
            fail "$name is required — declined"
            return 2
        fi
        note "skipped $name"
    fi
    return 0
}

# ====================================================================
# Per-tool installers — each one a function so the dispatcher stays
# uniform.
# ====================================================================

install_go() {
    case "$PM" in
        brew)   install_via_pm go ;;
        apt)    install_via_pm "" "golang-go" "" "" "" ;;
        dnf)    install_via_pm "" "" "golang" "" "" ;;
        pacman) install_via_pm "" "" "" "go" "" ;;
        apk)    install_via_pm "" "" "" "" "go" ;;
        *)      note "install go from https://go.dev/dl/"; return 1 ;;
    esac
}

install_docker() {
    if [ "$OS" = "macos" ]; then
        note "Docker Desktop required — install from https://www.docker.com/products/docker-desktop/"
        if ask_yes "open the download page?"; then open "https://www.docker.com/products/docker-desktop/"; fi
        return 1
    fi
    case "$PM" in
        apt)    install_via_pm "" "docker.io docker-compose-v2" "" "" "" ;;
        dnf)    install_via_pm "" "" "docker docker-compose-plugin" "" "" ;;
        pacman) install_via_pm "" "" "" "docker docker-compose" "" ;;
        apk)    install_via_pm "" "" "" "" "docker docker-compose" ;;
        *)      note "install docker manually"; return 1 ;;
    esac
}

install_git()   { install_via_pm git git git git git; }
install_gh()    { install_via_pm gh gh gh github-cli github-cli; }
install_gpg()   { install_via_pm gnupg gnupg gnupg2 gnupg gnupg; }
install_jq()    { install_via_pm jq jq jq jq jq; }

install_golangci_lint() {
    install_via_pm golangci-lint golangci-lint golangci-lint golangci-lint golangci-lint || \
        install_via_go "github.com/golangci/golangci-lint/v2/cmd/golangci-lint"
}

install_gosec()        { install_via_go "github.com/securego/gosec/v2/cmd/gosec"; }
install_govulncheck()  { install_via_go "golang.org/x/vuln/cmd/govulncheck"; }

install_gitleaks() {
    install_via_pm gitleaks gitleaks gitleaks gitleaks gitleaks || \
        install_via_go "github.com/gitleaks/gitleaks/v8"
}

install_goreleaser() {
    install_via_pm goreleaser goreleaser goreleaser goreleaser goreleaser || \
        install_via_go "github.com/goreleaser/goreleaser/v2"
}

install_syft() {
    case "$PM" in
        brew) install_via_pm syft ;;
        *)
            note "syft: curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin"
            return 1 ;;
    esac
}

install_cosign() {
    case "$PM" in
        brew) install_via_pm cosign ;;
        *)
            note "cosign: see https://docs.sigstore.dev/cosign/installation/"
            return 1 ;;
    esac
}

# ====================================================================
# Run the checks
# ====================================================================

declare -a MISSING_REQUIRED=()

run_check() {
    local label="$1" required="$2" check_cmd="$3" install_fn="$4"
    if check_and_install "$required" "$label" "$check_cmd" "$install_fn"; then
        return 0
    else
        MISSING_REQUIRED+=("$label")
        return 0  # don't abort the whole run yet — report all at end
    fi
}

hdr "Required for build"
run_check "go (>=1.25)"      1 "command -v go"     install_go
run_check "git"              1 "command -v git"    install_git

hdr "Required for dev-db"
run_check "docker"           1 "command -v docker" install_docker
run_check "docker compose"   1 "docker compose version" install_docker
run_check "jq"               1 "command -v jq"     install_jq

hdr "Required for tests + lint"
run_check "golangci-lint"    1 "command -v golangci-lint" install_golangci_lint
run_check "gosec"            1 "command -v gosec"          install_gosec
run_check "govulncheck"      1 "command -v govulncheck"    install_govulncheck

hdr "Recommended"
run_check "gh (GitHub CLI)"  0 "command -v gh"     install_gh
run_check "gpg (tag signing)" 0 "command -v gpg"   install_gpg
run_check "gitleaks"         0 "command -v gitleaks" install_gitleaks

hdr "Release-time (optional)"
run_check "goreleaser"       0 "command -v goreleaser" install_goreleaser
run_check "syft (SBOM)"      0 "command -v syft"   install_syft
run_check "cosign (keyless)" 0 "command -v cosign" install_cosign

# ====================================================================
# Summary
# ====================================================================

hdr "Summary"
if [ ${#MISSING_REQUIRED[@]} -eq 0 ]; then
    ok "all required dependencies satisfied"
    note "next: scripts/start.sh to bring up the full dev stack"
    exit 0
else
    fail "missing required: ${MISSING_REQUIRED[*]}"
    note "re-run scripts/bootstrap.sh to retry, or install manually"
    exit 2
fi
