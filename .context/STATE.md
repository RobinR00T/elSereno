---
phase: post-1.0
status: v1.0.0 released, v1.0.1 polish queued
last-updated: 2026-04-21
token-budget: 300
---

# Current state

**Phase**: Post-1.0 polish.
**Last tagged release**: **v1.0.0 on 2026-04-20**
  (https://github.com/RobinR00T/elSereno/releases/tag/v1.0.0).
  12 assets: 5 archives (darwin/linux × amd64/arm64 + sqlite
  linux-amd64) × SHA-256 checksums + 6 CycloneDX SBOMs +
  cosign-signed `checksums.txt.sig`. Tag signed with GPG
  ACE3B86BACACE7D6.
**v1.0.1 queued**: cosign `--bundle` + SLSA generator v2.1.0 +
  pandoc 3.9.0.2 pin + README badges. Source-level code
  unchanged between 1.0.0 and 1.0.1; only release-surface
  polish. Tag pending re-cut after the pandoc version-tag fix
  (`cab26e4`).
**Repo**: `RobinR00T/elSereno`, **private**. Pending operator
  decision to flip to public.
**In progress**: nothing.
**Blockers**: none.

## Known release carry-overs (post-1.0.1)
- GHCR docker image publishing (buildx driver + owner-slug
  rewrite + `--attest=type=sbom`); disabled in v1.0.0.
- `.intoto.jsonl` SLSA provenance assets on the release (fixed
  by v2.1.0 generator bump; validates on the v1.0.1 tag push).
- Docs ingestion into `/admin/security` from the GH Security
  tab (needs the public-repo flip first).

## Live services (preview-start)
- dashboard         127.0.0.1:8787
- dev-db (pg 16)    127.0.0.1:5433
- dev-adminer       127.0.0.1:8080
- test-simulators   127.0.0.1:5434
- banner-sim        127.0.0.1:9999

## Open questions
- Flip repo to public before cutting v1.1? (affects Scorecard +
  CodeQL + OSV visibility).
