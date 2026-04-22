---
phase: v1.4-in-flight
status: v1.3.0 tagged locally (unpushed); v1.4 chunk 1 landed (offensive sip gate)
last-updated: 2026-04-23
token-budget: 300
---

# Current state

**Phase**: v1.4 chunk 1 landed on `main` (`9038e4b`). v1.3.0 signed
locally (unpushed). Full PBX-discovery cycle shipped: SIP + IAX2 +
pbxhttp, 15 PBX brand fingerprints across the three plugins, plus
the offensive SIP write-gate that turns the deny-all default proxy
into a method-allowlisted forwarder. v1.2.0 + v1.3.0 + the 25
unpushed commits all waiting on the operator to restore `GH_TOKEN`
and push.

**Shipped releases** (in git history):
- v1.0.0 (2026-04-20) — scaffold + supply-chain baseline.
- v1.0.1 (2026-04-21) — release-surface polish.
- v1.1.0 (2026-04-21) — SSE + seccomp + OPC UA + wardial.
- v1.2.0 (2026-04-22, local) — DB panels + OPC UA write gate
  + Handle loops × 5 + dial backends + SLSA via Attestations
  API + SyncFromFile + SQLite retired.
- **v1.3.0** (2026-04-22, local) — PBX discovery (SIP + IAX2 +
  pbxhttp). 16 plugins in default build (up from 13 at v1.2.0).
  See `.context/snapshots/v1.3.0-pbx-discovery.md`.

**v1.3.0 chunks** (all landed):
- `e8278e5` chunk 1a — SIP OPTIONS probe on 5060/udp+tcp with
  15-vendor matcher (Asterisk, FreePBX, 3CX, Cisco UCM, Cisco
  SIP GW, Mitel, Avaya, Yeastar, Grandstream, Fanvil, Yealink,
  Kamailio, OpenSIPS, FreeSWITCH, SER).
- `ca68a3a` chunk 1b — IAX2 NEW/HANGUP probe on 4569/udp. RFC
  5456 full-frame parser + subclass classifier. Mini-frame-
  length-mismatch guard.
- `abd296d` chunk 1c — pbxhttp HTTP(S) admin-UI fingerprint on
  443 (also works on 80 / 8080 / 8088 / 5001 / 8443 with
  overridden Scheme). 15 PBX platform fingerprints via
  Server / title / body markers. PBX-likely heuristic for
  unmatched-brand HTTP responders with PBX-ish body text.
  InsecureSkipVerify defaulted true (PBX self-signed certs
  are ubiquitous; documented gosec waiver).

**16 protocol plugins in the default build**:
  atg, atmodem, bacnet, banner, dnp3, enip, fox, hartip, iax2,
  iec104, modbus, opcua, pbxhttp, s7, sip, xot.

**v1.4 in flight**:
- `9038e4b` **chunk 1** — offensive SIP write-gate
  (`offensive/write/sip/`). Method allowlist via
  `AllowedMethod{Method string}`; always-safe set
  (OPTIONS/ACK/BYE/CANCEL/PRACK) always passes; gated
  methods (INVITE/REGISTER/MESSAGE/SUBSCRIBE/NOTIFY/REFER/
  PUBLISH/UPDATE/INFO) require operator allowlist. Refusal
  is a canonical `SIP/2.0 405 Method Not Allowed` with an
  `Allow:` header listing the permitted methods. 13 tests;
  race-clean; gosec clean; ADR-040 template preserved.

**v1.4 remaining chunks** (planned):
- **chunk 2**: offensive pbxhttp write-gate (HTTP path +
  method allowlist, 405/403 refusal).
- **chunk 3**: offensive iax2 write-gate (subclass allowlist,
  HANGUP or REJECT refusal; needs UDP-proxy framework support
  — may pivot to TCP-over-UDP relay or defer).
- **chunk 4**: CLI wiring —
  `elsereno write sip --target h:p --method INVITE --accept-writes
   --confirm-target h:p --confirm-token T` (and the pbxhttp /
  iax2 analogues).
- **chunk 5**: TR-069/CWMP fingerprint on 7547/tcp.
- **chunk 6**: VoIP-SIP dial backend subprocess
  (`elsereno-dial-voip-sip` — seccomp-pair split since the parent
  process can't socket()).
- **chunk 7**: `dial batch --backend` CLI wiring to
  Backend.Deliver.
- **chunk 8**: BACnet full UDP relay.
- **chunk 9**: OPC UA per-NodeId allowlist.
- **chunk 10**: audit daemon for cross-process JSONL.
- **chunk 11**: seccomp arg-level filtering.
- **chunk 12**: HTTP paths beyond `/` for pbxhttp
  (`/admin/config.php` / `/webclient/` / `/ccmadmin/`).

**Unpushed work** (22 commits on local `main` ahead of
`origin/main`), grouped by tag:

```
<v1.3.0>   abd296d feat(v1.3 chunk 1c): pbxhttp
           46f3818 docs(memory): refresh state for v1.3-in-flight
           ca68a3a feat(v1.3 chunk 1b): IAX2
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
all v1.1/v1.2/v1.3 work is pushed; revoke after at
https://github.com/settings/personal-access-tokens.

**Repo**: `RobinR00T/elSereno`, **private**. Flip to public is
a post-push operator decision.

**Live services** (preview-start / dev-db helper):
- dashboard 127.0.0.1:8787
- dev-db (pg 16) 127.0.0.1:5433 (via scripts/dev-db.sh)

## Open questions

- Push 22 commits + 3 unpushed signed tags (v1.1.0, v1.2.0,
  v1.3.0) to GitHub in one go, or one tag at a time with a
  smoke-verify between each? (Recommended: one tag at a time,
  so the release-smoke check validates the binary artifacts at
  each step.)
- Flip repo public now (before the big push) or after v1.3?
- v1.4 leadoff: offensive write-gated PBX proxies (immediate
  continuation of v1.3) vs TR-069 (orthogonal fingerprint)?
