#!/usr/bin/env bash
# release-smoke.sh — post-push release verification for an
# ElSereno tag. Run after `git push origin <tag>` succeeds and
# the release workflow has uploaded the archives + GHCR image.
#
# Usage:
#   scripts/release-smoke.sh v1.1.0
#
# Exits 0 if every check passes, 1 otherwise.

set -euo pipefail

TAG="${1:?usage: release-smoke.sh <tag>}"
REPO="RobinR00T/elSereno"
LOWER_REPO="robinr00t/elsereno"
IDENTITY_REGEXP="https://github.com/${REPO}/.*"
OIDC_ISSUER="https://token.actions.githubusercontent.com"
WORK="$(mktemp -d -t elsereno-smoke-XXXX)"
trap 'rm -rf "$WORK"' EXIT

pass() { printf '  \033[32m[ok]\033[0m %s\n' "$1"; }
fail() { printf '  \033[31m[fail]\033[0m %s\n' "$1"; exit 1; }
note() { printf '  \033[34m[--]\033[0m %s\n' "$1"; }

need() {
    command -v "$1" >/dev/null 2>&1 || fail "missing tool: $1"
}

echo "== tools =="
need cosign
need curl
need shasum
need jq
need docker
pass "cosign, curl, shasum, jq, docker present"

echo
echo "== release assets ($TAG) =="
RELEASE_BASE="https://github.com/${REPO}/releases/download/${TAG}"
curl -fLo "$WORK/checksums.txt"        "$RELEASE_BASE/checksums.txt"        || fail "checksums.txt not on release"
curl -fLo "$WORK/checksums.txt.bundle" "$RELEASE_BASE/checksums.txt.bundle" || fail "checksums.txt.bundle not on release"
pass "checksums.txt + checksums.txt.bundle downloaded"

echo
echo "== cosign verify-blob =="
cosign verify-blob \
    --bundle "$WORK/checksums.txt.bundle" \
    --certificate-identity-regexp "$IDENTITY_REGEXP" \
    --certificate-oidc-issuer     "$OIDC_ISSUER" \
    "$WORK/checksums.txt" >/dev/null 2>&1 \
    || fail "cosign verify-blob failed on checksums.txt"
pass "checksums.txt signature verified against Sigstore transparency log"

echo
echo "== GHCR image =="
IMAGE="ghcr.io/${LOWER_REPO}:${TAG}"
docker pull --quiet "$IMAGE" >/dev/null 2>&1 || fail "docker pull $IMAGE"
pass "pulled $IMAGE"

cosign verify "$IMAGE" \
    --certificate-identity-regexp "$IDENTITY_REGEXP" \
    --certificate-oidc-issuer     "$OIDC_ISSUER" >/dev/null 2>&1 \
    || fail "cosign verify failed on $IMAGE"
pass "manifest signature verified against Sigstore transparency log"

echo
echo "== SBOM attestation =="
SBOM="$WORK/sbom.json"
if cosign download sbom "$IMAGE" > "$SBOM" 2>/dev/null; then
    COMPONENTS=$(jq -r '.components | length // 0' "$SBOM" 2>/dev/null || echo 0)
    if [ "$COMPONENTS" -gt 0 ]; then
        pass "CycloneDX SBOM has $COMPONENTS components"
    else
        note "SBOM downloaded but no components parsed (format mismatch?)"
    fi
else
    note "cosign download sbom returned no SBOM — expected for images without sbom: true"
fi

echo
echo "== runtime smoke =="
VERSION_OUT=$(docker run --rm "$IMAGE" version 2>&1 | head -1)
case "$VERSION_OUT" in
    "elsereno $TAG"*) pass "image prints 'elsereno $TAG'" ;;
    *)                fail "unexpected version output: $VERSION_OUT" ;;
esac

PLUGINS_COUNT=$(docker run --rm "$IMAGE" plugins list 2>&1 | wc -l | tr -d ' ')
if [ "$PLUGINS_COUNT" -ge 13 ]; then
    pass "plugins list reports $PLUGINS_COUNT plugins (≥13 expected for v1.1 with OPC UA)"
else
    fail "plugins list only returned $PLUGINS_COUNT plugins; OPC UA missing?"
fi

echo
echo "== summary =="
echo "  release $TAG verified end-to-end"
