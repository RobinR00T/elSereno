---
phase: v1.3-in-flight
status: v1.2.0 tagged locally (unpushed); v1.3 chunk 1a+1b landed on main (SIP + IAX2 plugins)
last-updated: 2026-04-22
token-budget: 300
---

# Current state

**Phase**: v1.3 chunk 1 (PBX discovery plugin set) in flight on
`main`. v1.2.0 tag is signed locally but unpushed — the full
cycle of v1.2 is ready to ship as soon as the operator restores
`GH_TOKEN` and pushes.

**Shipped releases** (in git history):
- v1.0.0 (2026-04-20) — scaffold + supply-chain baseline.
- v1.0.1 (2026-04-21) — release-surface polish.
- v1.1.0 (2026-04-21) — SSE + seccomp + OPC UA + wardial.
- **v1.2.0** (2026-04-22, local) — DB panels + OPC UA write
  gate + Handle loops × 5 + dial backends + SLSA via
  Attestations API + SyncFromFile + SQLite retired. See
  `.context/snapshots/v1.2-db-panels-opcua-gates-dial.md`.

**v1.3 in flight** (post-v1.2.0 commits on `main`):
- `e8278e5` **chunk 1a**: SIP OPTIONS probe on 5060/udp+tcp.
  15 known PBX brands identified (Asterisk, FreePBX, 3CX,
  Cisco UCM, Cisco SIP Gateway, Mitel, Avaya, Yeastar,
  Grandstream, Fanvil, Yealink, Kamailio, OpenSIPS,
  FreeSWITCH, SER). protocol_risk 70-90 by brand.
- `ca68a3a` **chunk 1b**: IAX2 NEW/HANGUP probe on 4569/udp.
  RFC 5456 full-frame parser + subclass classifier. ACCEPT /
  AUTHREQ / REJECT / HANGUP / PING / REG* all confirm IAX2 →
  protocol_risk=90. Mini-frame-length-mismatch guard against
  HTTP bytes tripping the IAX2 detector.
- **15 protocol plugins in the default build**:
  atg, atmodem, bacnet, banner, dnp3, enip, fox, hartip, iax2,
  iec104, modbus, opcua, s7, sip, xot.

**v1.3 chunk 1 remaining**:
- **chunk 1c** (pending, in progress): HTTP admin-UI
  fingerprints for FreePBX `/admin/config.php`, 3CX web UI,
  Yeastar management, Cisco UCM 443, Avaya 411 TLS,
  Grandstream/Fanvil/Yealink admin pages. Piggy-backs on the
  existing `banner` plugin's HTTP shape; extended with a
  vendor-string matcher table.
- **chunk 1 close**: snapshot of v1.3 chunk 1 findings.

**v1.3 subsequent chunks** (planned, see `TODO-vNext.md`):
- TR-069/CWMP fingerprint (7547/tcp).
- VoIP-SIP dial backend subprocess.
- Address `dial batch` CLI wiring to Backend.Deliver.
- BACnet full UDP relay.
- OPC UA per-NodeId allowlist.
- Audit daemon for cross-process JSONL.
- seccomp arg-level filtering.

**Unpushed work** (21 commits on local `main` ahead of
`origin/main`), grouped by tag:

```
<HEAD>     ca68a3a feat(v1.3 chunk 1b): IAX2
           e8278e5 feat(v1.3 chunk 1a): SIP
<v1.2.0>   8b9f245 docs(v1.2): close snapshot
           bc13248 feat(v1.2 extra): SyncFromFile
           26a7eda feat(v1.2 chunk 5): SLSA via Attestations API
           f2fa41c feat(v1.2 chunk 4): dial backends
           e8ff579 docs(authors): AUTHORS
           c04215f docs(manual): operator manual pack
           b5cb020 chore(v1.2): retire SQLite
           2c1a70e feat(v1.2 chunk 3): Handle loops × 5
           caa5b41 feat(v1.2 chunk 2): OPC UA write gating
           378a701 chore(v1.2 polish): CSP + readyz + allowlist
           8370b18 feat(v1.2 chunk 1): DB panels
           0c15398 docs(v1.2): planning snapshot
           c10a7d1 chore(v1.1 polish): release-smoke.sh
<v1.1.0>   0238f15 docs(v1.1): close snapshot
           8895148 feat(v1.1 chunk 8): wardialing batch
           bd90591 feat(v1.1 chunk 7): OPC UA plugin
           3af6c1f feat(v1.1 chunk 6): seccomp-bpf
           2fa03d3 feat(v1.1 chunk 5): GHCR docker
           fc7c4fe feat(v1.1 chunk 4a): SSE dashboard
<v1.0.1>   (already at origin/main)
```

**Bootstrap PAT**: still live. Operator asked to keep it until
all v1.1/v1.2 work is pushed; revoke after at
https://github.com/settings/personal-access-tokens.

**Repo**: `RobinR00T/elSereno`, **private**. Flip to public is
a post-push operator decision.

**Live services** (preview-start / dev-db helper):
- dashboard 127.0.0.1:8787
- dev-db (pg 16) 127.0.0.1:5433 (via scripts/dev-db.sh)

## Open questions
- Sign v1.3.0 once chunk 1c lands, or wait for chunks 2+
  (TR-069, VoIP backend, etc.) to accumulate?
- Flip repo public now (before the big push) or after v1.3?
