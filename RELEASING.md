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

The docker pipeline (v1.1+) uses `dockers_v2` with a buildx
driver set up by `docker/setup-buildx-action@v3` and QEMU from
`docker/setup-qemu-action@v3`. Both `linux/amd64` and
`linux/arm64` images are pushed to
`ghcr.io/robinr00t/elsereno:<tag>` and combined into a multi-arch
manifest at `:<tag>` and `:latest`. Each tagged manifest carries
a CycloneDX SBOM attestation (`--attest=type=sbom` via
goreleaser's native `sbom: true`), a SLSA-format provenance
attestation (`--attest=type=provenance,mode=max`), and a cosign
keyless signature on the manifest digest (`docker_signs` block).

## Post-release

1. Cross-verify published artefact checksums against the local
   dry-run.
2. Verify the sigstore transparency log entry
   (`rekor-cli search --sha <checksum>`).
3. Verify the docker manifest:
   ```sh
   cosign verify ghcr.io/robinr00t/elsereno:v1.1.0 \
     --certificate-identity-regexp 'https://github.com/RobinR00T/elSereno/.*' \
     --certificate-oidc-issuer     'https://token.actions.githubusercontent.com'
   cosign download sbom ghcr.io/robinr00t/elsereno:v1.1.0 | jq '.components | length'
   ```
4. Run the post-push smoke: `scripts/release-smoke.sh <tag>` —
   downloads checksums + bundle, runs `cosign verify-blob`,
   pulls the GHCR manifest, runs `cosign verify` on it,
   downloads the CycloneDX SBOM, and executes `docker run
   <tag> version` + `plugins list` as a runtime sanity check.
   Exits 0 on success; any failure prints a red `[fail]` line.
5. Draft the GitHub release body from the CHANGELOG entry.
6. Announce on relevant channels.

## 1.0.0 gate

The 1.0 tag is the first release where operator field-use is
officially supported. Additional preconditions on top of the
pre-release checklist:

1. **Every residual risk** in `.context/threat-model/*.md` is
   either resolved or tracked in a GitHub issue with a target
   version.
2. **STRIDE coverage**: no `internal/` or `offensive/` package
   is missing from the threat-model index.
3. **Supply-chain**: OpenSSF Scorecard ≥ 8.0; SLSA L3 provenance
   verifies on a `--snapshot` release produced by the release
   workflow; `osv-scanner` clean.
4. **Benchmarks**: `benchmarks/baseline.txt` captured over ≥ 6
   samples; `benchstat` reports no regression ≥ 10 % vs the
   0.1.0 baseline.
5. **Docs**: every CLI verb has a man page under `man/man1/`;
   `elsereno api openapi -o docs/openapi.yaml` emits zero diff.
6. **Sec panel**: `/admin/security` renders with every control
   in the green/info state when compiled without
   `-tags offensive`.
7. **Release-gate**: `make release-gate` exits 0 on a clean
   working tree.

Run the gate locally:

```sh
make release-gate
```

Any FAIL line blocks the tag. Skipped lines (tools missing
locally) still require the CI workflow's equivalent job to be
green.

## Rollback

1. `gh release delete v0.1.0 --yes` to remove the release entry.
2. `git tag -d v0.1.0 && git push origin :refs/tags/v0.1.0` to
   delete the tag on origin.
3. The docker manifest remains in ghcr until a separate `docker
   manifest rm` is issued — do this second to avoid a failed
   pull on a stale tag.
4. Open an issue documenting the rollback reason; link it from
   the next release's CHANGELOG.
