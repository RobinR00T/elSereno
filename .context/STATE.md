---
phase: v1.2-released
status: v1.2.0 tagged locally; release workflow runs on push
last-updated: 2026-04-22
token-budget: 300
---

# Current state

**Phase**: v1.2 closed on `main` (RobinR00T/elSereno, private).
Feature work done; the tag is cut locally and the release
workflow will run on `git push origin v1.2.0`.

**Shipped releases**:
- **v1.0.0** (2026-04-20) — scaffold + supply-chain baseline.
- **v1.0.1** (2026-04-21) — release-surface polish.
- **v1.1.0** (2026-04-21) — SSE + seccomp + OPC UA + wardial.
- **v1.2.0** (2026-04-22, local) — DB-backed panels + OPC UA
  write gate + full Handle loops for dnp3/iec104/hartip/atg/fox
  + dial backend interface + SLSA via GitHub Attestations API
  + SyncFromFile + SQLite retirement + operator manual pack.
  See `.context/snapshots/v1.2-db-panels-opcua-gates-dial.md`.

**v1.3 carry-overs**:
- VoIP-SIP dial backend (subprocess binary).
- BACnet full UDP relay.
- OPC UA per-NodeId allowlist (currently TypeID-granular only).
- `dial batch` CLI wiring to call Backend.Deliver.
- seccomp arg-level filtering (openat O_WRONLY etc).
- Audit daemon for cross-process JSONL shared access.
- **PBX discovery plugin set** (Asterisk / FreePBX / 3CX /
  Cisco UCM / Mitel / Avaya / Yeastar / Grandstream / Fanvil /
  Yealink) — operator-requested; see `TODO-vNext.md`.

**Bootstrap PAT**: operator task — revoke at
https://github.com/settings/personal-access-tokens once v1.2
release assets are verified.

**Repo**: `RobinR00T/elSereno`, **private**. Flip to public is
a post-v1.2 operator decision (unlocks Scorecard + CodeQL + OSV).

**Live services** (preview-start):
- dashboard 127.0.0.1:8787
- dev-db (pg 16) 127.0.0.1:5433 (via scripts/dev-db.sh)
- test-simulators 127.0.0.1:5434

## Open questions
- Flip repo to public after v1.2? (unlocks Scorecard).
- v1.3 kickoff: PBX plugin first (operator priority) or VoIP
  backend first (completes chunk 4)?
