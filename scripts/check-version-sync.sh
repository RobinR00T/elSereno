#!/usr/bin/env bash
# check-version-sync.sh: assert the Go version is consistent across the
# places that must agree, or the build breaks on the lagging one.
#
# This is the enforced form of the invariant the Dockerfile documents in
# a comment. The 2026-09 pgx 5.11 / Go 1.26 Dependabot bump raised
# go.mod's `go` directive but left the Dockerfile and the CI matrix on
# 1.25, so `build-default (ubuntu-latest, 1.25)` failed with
# "go.mod requires go >= 1.26.0 (running go 1.25.x; GOTOOLCHAIN=local)".
#
# Compared on major.minor:
#   - go.mod           `go X.Y.Z`         (the module's minimum Go)
#   - Dockerfile       `ARG GO_VERSION=`  (the builder image Go)
#   - ci.yml matrix    the explicit `go:` include entry (not 'stable')
#   - devcontainer     `devcontainers/go:X.Y-...` image tag
#
# The dev container image joined the check on 2026-10-15: it had stayed
# on Go 1.23 while go.mod moved to 1.26, and the image sets
# GOTOOLCHAIN=local, so `go build` inside it failed with "go.mod
# requires go >= 1.26.0".
#
# Each read ends in `|| true` so that a missing line reaches the -z
# check below (exit 2 with a message) instead of stopping the script
# silently under `set -e -o pipefail`.
set -euo pipefail
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

mm() { cut -d. -f1,2; }

gomod=$(grep -E '^go [0-9]' go.mod | awk '{print $2}' || true)
gomod_mm=$(printf '%s' "$gomod" | mm)

docker=$(grep -E '^ARG GO_VERSION=' Dockerfile | head -1 | cut -d= -f2 || true)
docker_mm=$(printf '%s' "$docker" | mm)

# The minimum-Go matrix entry is the include that pins an explicit
# numeric version (the other entries use 'stable').
ci=$(grep -Eo "go: '[0-9][^']*'" .github/workflows/ci.yml | head -1 | sed -E "s/go: '([^']+)'/\1/" || true)
ci_mm=$(printf '%s' "$ci" | mm)

devc=$(grep -Eo 'devcontainers/go:[0-9]+\.[0-9]+' .devcontainer/devcontainer.json | head -1 | cut -d: -f2 || true)
devc_mm=$(printf '%s' "$devc" | mm)

fail=0
if [ -z "$gomod" ] || [ -z "$docker" ] || [ -z "$ci" ] || [ -z "$devc" ]; then
	echo "check-version-sync: could not read one of the versions (go.mod=$gomod dockerfile=$docker ci=$ci devcontainer=$devc)" >&2
	exit 2
fi
if [ "$gomod_mm" != "$docker_mm" ]; then
	echo "DRIFT: go.mod go $gomod_mm != Dockerfile GO_VERSION $docker_mm ($docker)" >&2
	fail=1
fi
if [ "$gomod_mm" != "$ci_mm" ]; then
	echo "DRIFT: go.mod go $gomod_mm != ci.yml minimum matrix entry $ci_mm ($ci)" >&2
	fail=1
fi
if [ "$gomod_mm" != "$devc_mm" ]; then
	echo "DRIFT: go.mod go $gomod_mm != .devcontainer image Go $devc_mm" >&2
	fail=1
fi
if [ "$fail" -ne 0 ]; then
	echo "Go version drift: keep go.mod, Dockerfile GO_VERSION, the ci.yml minimum matrix entry and the dev container image on the same major.minor." >&2
	exit 1
fi
echo "go version sync OK: go.mod=$gomod, Dockerfile=$docker, ci-min=$ci, devcontainer=$devc (all $gomod_mm)"
