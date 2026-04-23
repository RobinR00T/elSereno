# Releasing ElSereno

This document is the operator runbook for cutting a new release.
Assumes you are a maintainer with access to the signing keys.

Two flows are documented here:

- **Free-tier local-build flow** (default since v1.8.0) — all
  artefacts are produced locally with `goreleaser` and uploaded
  to GitHub Releases via `gh release upload`. No GitHub Actions
  minutes consumed. Verification: GPG-signed tag + SHA-256
  checksums + CycloneDX SBOMs.
- **CI-based flow (legacy, v1.0.x)** — originally used until
  v1.0.1 (pushed releases on every tag). Kept at the bottom of
  this document for operators with Actions billing active who
  want cosign keyless signatures + SLSA v1.0 attestations +
  GHCR multi-arch docker images.

## Prerequisites

Install the local build tools on your workstation:

```sh
brew install goreleaser syft            # build + SBOM
# cosign is optional — only needed for CI-based flow below
```

Minimum versions verified: goreleaser 2.15.3, syft 1.42.4.

GitHub CLI + a PAT with `Contents: read+write` permission on the
target repo:

```sh
gh auth login                           # or export GH_TOKEN=…
```

## Pre-release checklist

1. `make ci` green end-to-end (lint ×2, build ×3 variants, race,
   cover, fuzz smoke, sec suite, context-check). A failing CI
   blocks the tag.
2. `make release-gate` exits 0 (goreleaser snapshot build +
   govulncheck + gitleaks + benchmarks baseline check).
3. `.context/STATE.md` phase line reflects the closed phase.
4. `CHANGELOG.md` has a populated `[X.Y.Z]` section with date.
5. `.context/snapshots/vX.Y.Z-<name>.md` cycle close snapshot
   written.
6. `docs/openapi.yaml` up-to-date (`elsereno api openapi -o
   docs/openapi.yaml` regenerates it from code).

## Signing the tag

Every release tag is GPG-signed with the maintainer key
(`ACE3B86BACACE7D6` / Daniel Solís Agea). Downstream operators
verify with `git tag -v <tag>`.

```sh
git tag -s v1.8.0 -m "ElSereno v1.8.0 — <one-line summary>"
git push origin v1.8.0
```

## Free-tier local-build flow (default)

### 1. Build artefacts locally

From a clean worktree, from the tag commit:

```sh
git checkout v1.8.0                              # detached HEAD
goreleaser release --clean \
    --skip=publish,sign,docker,validate
git checkout main                                # back to working branch
```

Produces under `dist/`:

- 4 archives: `elsereno_<ver>_<os>_<arch>.tar.gz`
  (darwin/linux × amd64/arm64). Each archive bundles BOTH the
  read-only `elsereno` binary AND the `elsereno-offensive`
  variant.
- 4 CycloneDX SBOMs: `elsereno_<ver>_<os>_<arch>.tar.gz.cyclonedx.json`
  (one per archive, via syft).
- 1 `checksums.txt` with SHA-256 over every other file.

Skipped:
- `publish` — we'll upload manually via `gh` below.
- `sign` — cosign keyless needs GitHub Actions OIDC; not
  available in local builds.
- `docker` — GHCR push needs Actions auth + buildx + QEMU for
  cross-arch. Operators can build images locally if desired:
  `docker buildx build --platform linux/amd64,linux/arm64
  -t local/elsereno:<ver> .`.
- `validate` — skip strict worktree-clean check (we just did
  `git checkout` on a tag, which goreleaser flags as
  detached HEAD).

### 2. Write release notes

Write release notes to `/tmp/release-notes-vX.Y.Z.md`. Template:

```md
# ElSereno vX.Y.Z — <one-line theme>

<2-3 sentences summary>

## Highlights
<bullet list>

## Installation
<platform table + tar unpack>

## Examples
<2-3 copy-paste command blocks for the headline features>

## Verification
- SHA-256 table (paste from dist/checksums.txt)
- git tag -v vX.Y.Z (ACE3B86BACACE7D6)
- SBOM inspection with jq

## Supply-chain note
<transparency paragraph — which artefacts come with which
signatures, what is missing vs CI-based flow>
```

### 3. Create / upload to the GitHub Release

```sh
gh release create vX.Y.Z \
    dist/elsereno_X.Y.Z_*.tar.gz \
    dist/*.cyclonedx.json \
    dist/checksums.txt \
    --repo RobinR00T/elSereno \
    --title "vX.Y.Z — <title>" \
    --notes-file /tmp/release-notes-vX.Y.Z.md
```

If the release already exists (e.g. a previous Actions attempt
created an empty one), use `--clobber` on `gh release upload`
instead.

### 4. Post-release smoke

```sh
gh release view vX.Y.Z --repo RobinR00T/elSereno  # artefacts listed
curl -fLO https://github.com/RobinR00T/elSereno/releases/download/vX.Y.Z/checksums.txt
curl -fLO https://github.com/RobinR00T/elSereno/releases/download/vX.Y.Z/elsereno_X.Y.Z_darwin_arm64.tar.gz
shasum -a 256 -c checksums.txt
tar -xzf elsereno_X.Y.Z_darwin_arm64.tar.gz
./elsereno_X.Y.Z_darwin_arm64/elsereno version
./elsereno_X.Y.Z_darwin_arm64/elsereno plugins list | wc -l   # expect 17
```

### 5. Operator hygiene

```sh
# revoke the release PAT (it had Contents:read+write)
open https://github.com/settings/personal-access-tokens
# → revoke the "elsereno-push-XXX" entry

# delete the local token file if used
rm ~/.elsereno/gh-token 2>/dev/null || true
```

## CI-based flow (legacy, requires Actions billing)

Before v1.8.0 releases were produced by `.github/workflows/
release.yml` on every `v*` tag push. Operators with active
GitHub Actions billing can still use this flow — it adds:

- **Cosign keyless** signatures on `checksums.txt` (both
  `.bundle` and legacy `.sig`).
- **SLSA v1.0 provenance** attestations via
  `actions/attest-build-provenance@v2` (verified with
  `gh attestation verify <artefact>`).
- **GHCR docker images** signed with cosign on the manifest.

Current state: the workflow is gated to `workflow_dispatch:` so
it doesn't run on tag push automatically. To re-enable:

1. Restore billing at https://github.com/settings/billing.
2. Edit `.github/workflows/release.yml`: replace the
   `on: workflow_dispatch` block with the original
   `on: push: tags: ["v*"]` preserved in the header comment.
3. Push a new tag — the workflow runs goreleaser with publish +
   sign + docker enabled, uploads all artefacts + signatures.

Or run manually on an existing tag:

```sh
gh workflow run release.yml --ref v1.8.0 --repo RobinR00T/elSereno
```

(Requires `workflow: write` on the PAT.)

### Verification of CI-signed releases

```sh
# cosign bundle on checksums
cosign verify-blob \
    --certificate-identity-regexp 'https://github.com/RobinR00T/elSereno/.*' \
    --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
    --bundle checksums.txt.bundle checksums.txt

# SLSA v1.0 provenance
gh attestation verify elsereno_X.Y.Z_linux_amd64.tar.gz \
    --repo RobinR00T/elSereno

# GHCR docker manifest
cosign verify ghcr.io/robinr00t/elsereno:vX.Y.Z \
    --certificate-identity-regexp 'https://github.com/RobinR00T/elSereno/.*' \
    --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
```

## 1.0.0 gate (kept for reference)

The 1.0 gate applied to the first community release (which is
now v1.8.0). Preconditions:

1. Every residual risk in `.context/threat-model/*.md` either
   resolved or tracked.
2. STRIDE coverage: no `internal/` or `offensive/` package
   missing from the threat-model index.
3. Supply-chain: OpenSSF Scorecard ≥ 8.0; `osv-scanner` clean.
4. Benchmarks: `benchmarks/baseline.txt` captured over ≥ 6
   samples; `benchstat` reports no regression ≥ 10 % vs the
   last baseline.
5. Docs: every CLI verb has a man page under `man/man1/`;
   `elsereno api openapi -o docs/openapi.yaml` emits zero diff.
6. Sec panel: `/admin/security` renders with every control
   in green/info state when compiled without `-tags offensive`.
7. `make release-gate` exits 0 on a clean working tree.

## Rollback

If a release has to be pulled:

1. `gh release delete vX.Y.Z --yes --repo RobinR00T/elSereno`
   to remove the release entry.
2. Tags are NOT usually deleted (they're signed — operators
   might have pinned). If the bug is shipping-blocker, ship
   `vX.Y.(Z+1)` instead of retracting.
3. If a `vX.Y.Z` docker image was published to GHCR, delete
   it from the registry UI.
4. Open an issue documenting the rollback reason; link it from
   the release notes of the replacement version.

## Release-gate quick reference

```sh
make release-gate
```

Validates:
- README / SECURITY / LEGAL / CONTRIBUTING / CODE_OF_CONDUCT /
  NON-GOALS / CHANGELOG / SUPPLY-CHAIN / RELEASING / TODO
  present.
- `docs/protocols/` populated.
- `.context/threat-model/` populated.
- `goreleaser snapshot build` succeeds.
- `govulncheck ./...` clean.
- `gitleaks detect` clean.
- `benchmarks/baseline.txt` checked in.

Any FAIL line blocks the tag.
