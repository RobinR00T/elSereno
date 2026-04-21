---
phase: v1.1-released
status: v1.1.0 tagged locally; cosign + docker manifest verification pending first remote push
last-updated: 2026-04-21
token-budget: 300
---

# Current state

**Phase**: v1.1 closed on `main` (RobinR00T/elSereno, private).
Feature work done; the tag is cut locally and the release
workflow will run on `git push origin v1.1.0`.

**Shipped releases**:
- **v1.0.0** (2026-04-20) — 12 assets, GPG-signed tag
  ACE3B86BACACE7D6, missing SLSA `.intoto.jsonl`.
- **v1.0.1** (2026-04-21) — release-polish: cosign bundle
  (verified end-to-end with `cosign verify-blob --bundle
  checksums.txt.bundle` → OK), pandoc 3.9.0.2 pin, SLSA
  v2.1.0 generator (final step still hits upstream bug
  exit-27; wrapped non-blocking in release.yml).
- **v1.1.0** (2026-04-21, local) — closes the eight v1.1
  feature chunks: per-plugin offensive WriteGatedHandler,
  file-backed audit writer, offensive CLI network delivery,
  SSE `/api/v1/stream` + dashboard live-feed, GHCR docker
  image via `dockers_v2`, seccomp-bpf per-profile sandbox,
  OPC UA plugin on 4840, wardialing batch. See the closed
  snapshot at `.context/snapshots/v1.1-sse-sandbox-opcua-wardial.md`.

**v1.2 carry-overs** (already tracked in the closed snapshot):
- Findings / triage / runs DB tables + dashboard panels
  (ship alongside DB-backed audit Writer).
- OPC UA write-gating via `offensive/write/opcua/` + full
  SecureChannel / Session / Write handling.
- bacnet / dnp3 / iec104 / hartip / atg / fox full Handle
  loops (session primitives shipped in v1.1).
- Real PSTN / VoIP dial backend (batch currently records
  intent only).
- SLSA `.intoto.jsonl` upstream-bug fix (drop reusable
  workflow + call generator directly).

**Bootstrap PAT** (`elsereno` fine-grained) still live per
operator request until after the v1.1 push. Revoke at
https://github.com/settings/personal-access-tokens once the
v1.1 release assets are verified.

**Repo**: `RobinR00T/elSereno`, **private**. Flip to public is
a post-v1.1 operator decision that unlocks Scorecard + CodeQL
+ OSV full suite on the repo.

**Live services** (preview-start):
- dashboard 127.0.0.1:8787
- dev-db (pg 16) 127.0.0.1:5433
- dev-adminer 127.0.0.1:8080
- test-simulators 127.0.0.1:5434
- banner-sim 127.0.0.1:9999

## Open questions
- Flip repo to public after v1.1? (unlocks Scorecard,
  CodeQL, OSV).
- Timing of v1.2 kickoff vs. public-flip? (Public flip first
  means v1.2 gets full CodeQL coverage on every PR.)
