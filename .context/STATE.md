---
phase: v1.5-released
status: v1.5.0 tagged locally (unpushed); proxy listen shipped
last-updated: 2026-04-23
token-budget: 300
---

# Current state

**Phase**: v1.5.0 signed locally (unpushed). `elsereno proxy
listen` command shipped — operators can now run the v1.4 write-
gated handlers inline against a local TCP listener. Supports
all six gated plugins (sip / iax2 / pbxhttp / modbus / opcua /
bacnet) with per-plugin allowlist flags and a first end-to-end
test covering the full stack. v1.2.0 + v1.3.0 + v1.4.0 + v1.5.0
waiting on the operator to restore `GH_TOKEN` and push.

**Shipped releases** (in git history):
- v1.0.0 (2026-04-20) — scaffold + supply-chain baseline.
- v1.0.1 (2026-04-21) — release-surface polish.
- v1.1.0 (2026-04-21) — SSE + seccomp + OPC UA + wardial.
- v1.2.0 (2026-04-22, local) — DB panels + OPC UA write gate
  + Handle loops × 5 + dial backends + SLSA via Attestations
  API + SyncFromFile + SQLite retired.
- v1.3.0 (2026-04-22, local) — PBX discovery (SIP + IAX2 +
  pbxhttp). 16 plugins default build; 15 PBX brand
  fingerprints.
- **v1.4.0** (2026-04-23, local) — offensive PBX write-gates
  + BACnet UDP relay + TR-069/CWMP fingerprint. 17 plugins
  default build; 4 offensive write-gated proxies (up from 2).
  See `.context/snapshots/v1.4.0-offensive-pbx-and-cwmp.md`.
- **v1.5.0** (2026-04-23, local) — `elsereno proxy listen`
  CLI goes live. All six write-gated plugins runnable via a
  single command (--plugin {sip|iax2|pbxhttp|modbus|opcua|
  bacnet} + per-plugin allowlist flags). First end-to-end
  test of the full proxy stack. See
  `.context/snapshots/v1.5.0-proxy-listen.md`.

**v1.4.0 chunks** (all landed):
- `9038e4b` chunk 1 — offensive SIP write-gate. Method allowlist
  via net/textproto request-line parser. 405 refusal with
  Allow header.
- `482263f` chunk 2 — offensive pbxhttp write-gate. (method,
  path) allowlist via net/http's server parser. 405 / 403
  refusals.
- `b0d3ea7` chunk 3 — offensive iax2 write-gate. Subclass
  allowlist with UDP per-datagram relay. HANGUP refusal.
- `26ca8df` chunk 4 — CLI dry-run wiring for all three PBX
  gates. `elsereno write {sip,iax2,pbxhttp} dry-run`.
- `02e705f` chunk 5 — TR-069 / CWMP ACS fingerprint on 7547.
  15 ACS vendor fingerprints. 17 plugins in default build.
- `e4dc2a6` chunk 6 — BACnet/IP UDP write-gate. Service-choice
  allowlist. Abort-PDU refusal with security-error reason.
  Closes the v1.2 carry-over.

**17 protocol plugins in the default build**:
  atg, atmodem, bacnet, banner, cwmp, dnp3, enip, fox, hartip,
  iax2, iec104, modbus, opcua, pbxhttp, s7, sip, xot.

**5 offensive write-gated proxies** (ADR-040 pattern):
  modbus, opcua, sip, iax2, pbxhttp, bacnet.

**v1.5.0 chunks** (all landed):
- `e8bd030` chunk 1 — proxy listen for sip/iax2/pbxhttp.
- `1172eae` chunk 2 — extend proxy listen to modbus/opcua/
  bacnet + first end-to-end integration test.

**v1.6+ roadmap** (see `TODO-vNext.md`):
- OPC UA per-NodeId allowlist (tighten write gate from
  service-TypeID to specific Object_Identifiers).
- BACnet per-object allowlist (same shape, ASN.1 BER parsing).
- SIP To-URI E.164 prefix allowlist for INVITE (toll-
  destination blocking).
- REGISTER AOR allowlist.
- CWMP offensive proxy (SOAP RPC allowlist).
- HTTP paths beyond `/` for pbxhttp fingerprint (vendor-
  specific `/admin/config.php`, `/webclient/`, `/ccmadmin/`).
- VoIP-SIP dial backend subprocess.
- `dial batch --backend` CLI wiring.
- Audit daemon for cross-process JSONL.
- seccomp arg-level filtering.
- `--allow-file` for reading allowlists from YAML/JSON.
- Runtime reload of the proxy listen allowlist (SIGHUP).

**Unpushed work** (33 commits on local `main` ahead of
`origin/main`), grouped by tag:

```
<v1.5.0>   1172eae feat(v1.5 chunk 2): extend proxy listen
           e8bd030 feat(v1.5 chunk 1): proxy listen sip/iax2/pbxhttp
<v1.4.0>   7457016 docs(v1.4): close PBX-write-gate cycle
           e4dc2a6 feat(v1.4 chunk 6): bacnet UDP write-gate
           02e705f feat(v1.4 chunk 5): cwmp TR-069
           26ca8df feat(v1.4 chunk 4): CLI write sip/iax2/pbxhttp
           b0d3ea7 feat(v1.4 chunk 3): iax2 write-gate
           482263f feat(v1.4 chunk 2): pbxhttp write-gate
           b43a472 docs(state): v1.4 chunk 1 landed
           9038e4b feat(v1.4 chunk 1): sip write-gate
<v1.3.0>   3ceebef docs(v1.3): close PBX-discovery cycle
           abd296d feat(v1.3 chunk 1c): pbxhttp
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

**Bootstrap PAT**: still live. Operator asked to keep it
until all v1.1/v1.2/v1.3/v1.4 work is pushed; revoke after at
https://github.com/settings/personal-access-tokens.

**Repo**: `RobinR00T/elSereno`, **private**. Flip to public
is a post-push operator decision.

**Live services** (preview-start / dev-db helper):
- dashboard 127.0.0.1:8787
- dev-db (pg 16) 127.0.0.1:5433 (via scripts/dev-db.sh)

## Open questions

- Operator push strategy: one tag at a time (smoke-verify each)
  vs all-in-one push of 31 commits + 4 tags?
- v1.5 leadoff chunk: `proxy listen` CLI (immediate operator
  value) vs OPC UA per-NodeId (deeper protocol work)?
- Public repo flip: before or after the big push?
