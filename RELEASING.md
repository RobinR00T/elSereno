# Releasing ElSereno

This document is the operator runbook for cutting a new release.
Assumes you are a maintainer with access to the signing keys and
the GitHub release workflow.

## Prerequisites

Install the release-time tools on your workstation:

```sh
brew install goreleaser syft cosign
```

Minimum versions verified: goreleaser 2.15.3, syft 1.42.4,
cosign 3.0.6.

## Pre-release checklist

1. `make ci` green end-to-end (lint ×2, build ×3 variants, race,
   cover, fuzz smoke, sec suite, context-check). A failing CI
   blocks the tag.
2. `.context/STATE.md` phase line reflects the closed phase.
3. `CHANGELOG.md` has a populated **Unreleased** block — move it
   to the dated release section.
4. `docs/openapi.yaml` is up-to-date (`elsereno api openapi -o
   docs/openapi.yaml` regenerates it from code).
5. No `gitleaks`, `govulncheck`, `trivy`, or `go-licenses`
   findings.

## Dry-run

From a clean worktree (no `dist/`):

```sh
goreleaser check                                        # validates config
goreleaser build --snapshot --clean \
    --id elsereno-default --id elsereno-offensive       # skip sqlite CGO
goreleaser release --snapshot --clean \
    --skip sign,publish,docker,sbom                      # local-only
```

Dry-run produces 8 binaries under `dist/` — 2 build variants ×
4 OS/arch combinations (darwin/linux × amd64/arm64). The sqlite
variant is skipped in a macOS dry-run because CGO cannot
cross-compile from macOS to Linux without a Linux sysroot; the
GitHub Actions runner (ubuntu-latest) builds all three variants.

Smoke the artefacts:

```sh
dist/elsereno-default_darwin_arm64_v8.0/elsereno version
dist/elsereno-default_darwin_arm64_v8.0/elsereno plugins list
dist/elsereno-offensive_darwin_arm64_v8.0/elsereno-offensive \
    exploit list
```

## SBOM

goreleaser invokes `cyclonedx-gomod` during the real release. For
local verification you can generate a CycloneDX SBOM with syft:

```sh
syft dist/elsereno-default_darwin_arm64_v8.0/elsereno \
    -o cyclonedx-json > dist/elsereno_default_sbom.cyclonedx.json
```

The workflow's `sboms:` block ships one SBOM per archive on real
releases.

## Signing

Real releases (not `--snapshot`) pass through `cosign sign-blob`
against the checksums file using the release workflow's keyless
Sigstore identity (GitHub Actions OIDC). Operators on the receiving
end verify with:

```sh
cosign verify-blob \
    --certificate-identity-regexp 'https://github.com/elsereno/elsereno/.*' \
    --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
    --signature checksums.txt.sig \
    checksums.txt
```

## Tagging + pushing

Cut the tag on the release commit:

```sh
git tag -s v0.1.0 -m "ElSereno 0.1.0 — F0-F6 closed"
git push origin v0.1.0
```

The `release` workflow picks up the tag and runs
`goreleaser release --clean` with the full pipeline (archives +
docker + sbom + sign + publish).

## Post-release

1. Cross-verify published artefact checksums against the local
   dry-run.
2. Verify the sigstore transparency log entry
   (`rekor-cli search --sha <checksum>`).
3. Draft the GitHub release body from the CHANGELOG entry.
4. Announce on relevant channels.

## Rollback

1. `gh release delete v0.1.0 --yes` to remove the release entry.
2. `git tag -d v0.1.0 && git push origin :refs/tags/v0.1.0` to
   delete the tag on origin.
3. The docker manifest remains in ghcr until a separate `docker
   manifest rm` is issued — do this second to avoid a failed
   pull on a stale tag.
4. Open an issue documenting the rollback reason; link it from
   the next release's CHANGELOG.
