---
phase: v1.10-released
status: v1.10.0 tagged locally; SIP REGISTER AOR allowlist (registration-hijack mitigation)
last-updated: 2026-04-24
token-budget: 300
---

# Current state

**Phase**: v1.10.0 firmado localmente (pendiente de publicar
en GitHub Releases). Single-chunk cycle que añade el gemelo
anti-registration-hijack del INVITE prefix gate de v1.9 chunk
5: allowlist exact-match de AoRs permitidas para REGISTER,
fail-closed ante To: malformados, refusal protocol-native
(SIP 403 + X-Elsereno-Gate-Reason). Hash backwards-compat:
operadores sin `AllowedAORs` siguen con sus tokens v1.9 / v1.4
válidos.

v1.9.0 sigue publicado en GitHub Releases. v1.10.0 pendiente de
build local + gh release upload.

v1.8.0 sigue publicado en
https://github.com/RobinR00T/elSereno/releases/tag/v1.8.0.

GitHub Actions workflows quedaron desactivados (trigger
cambiado a `workflow_dispatch` only) después de que todos
fallaran con "payment failed / spending limit reached" — el
proyecto opera ahora en el tier gratuito de GitHub. Si en el
futuro se restaura billing, los workflows se pueden reactivar
editando el `on:` stanza en cada `.github/workflows/*.yml`
(los triggers originales quedan preservados en comentarios).

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
- **v1.6.0** (2026-04-23, local) — `--allow-file` YAML loader
  for the proxy listen command + OPC UA per-NodeId allowlist
  (opt-in tightening of the v1.2 write-gate from service-
  TypeID to specific Object_Identifier NodeIds). Backwards-
  compatible with v1.2 tokens when AllowedNodeIDs is empty.
  See `.context/snapshots/v1.6.0-allowfile-and-nodeid.md`.
- **v1.7.0** (2026-04-23, local) — YAML round-trip emitter
  (`write dry-run --emit-allow-file`) + new dry-runs for opcua
  and bacnet (`--node-id ns=N;i=M` for OPC UA honours the
  v1.6 per-NodeId extension). Write command surface now
  symmetric across all five proxy-session-capable plugins
  (sip / iax2 / pbxhttp / opcua / bacnet). Modbus proxy-
  session dry-run is a v1.8 carry-over. See
  `.context/snapshots/v1.7.0-yaml-round-trip.md`.
- **v1.8.0** (2026-04-23, local) — FOFA (fofa.info) +
  ZoomEye (zoomeye.org) attack-surface input clients.
  Library-level, matches the Shodan / Censys pattern. 10
  tests across the two packages. CLI wire-up decision is a
  v1.9 carry-over. See `.context/snapshots/v1.8.0-fofa-
  zoomeye-inputs.md`.
- **v1.10.0** (2026-04-24, local) — SIP REGISTER AOR allowlist
  (anti-registration-hijack). Twin of v1.9 chunk 5's INVITE
  prefix gate. Library + CLI (`--aor`) + YAML (`aors:`) +
  proxy-listen wiring + 15 tests. Hash backwards-compat
  preserves v1.4 / v1.9 tokens. See
  `.context/snapshots/v1.10.0-sip-aor.md`.
- **v1.9.0** (2026-04-24, local) — 5 chunks: OPC UA NodeID
  YAML round-trip, Modbus proxy-session dry-run, CLI wire-up
  for Shodan/Censys/FOFA/ZoomEye via `scan --input`, ONYPHE
  input client (5th provider), SIP INVITE To-URI prefix
  allowlist for toll-fraud mitigation. 33 new tests. See
  `.context/snapshots/v1.9.0-roundtrip-inputs-toll.md`.

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

**v1.6.0 chunks** (all landed):
- `a5ee374` chunk 1 — `elsereno proxy listen --allow-file`
  YAML loader. 10 tests.
- `f76b3f2` chunk 2 — OPC UA per-NodeId allowlist. 8 tests.

**v1.7.0 chunks** (all landed):
- `0f31d6e` chunk 1 — `write dry-run --emit-allow-file`.
- `65e5382` chunk 2 — `write opcua dry-run` + `write bacnet
  dry-run`.

**v1.8.0 chunks** (all landed):
- `da41262` chunk 1 — FOFA input client + 5 tests.
- `315ad0c` chunk 2 — ZoomEye input client + 5 tests.

**v1.9.0 chunks** (all landed):
- `08ec93a` chunk 1 — OPC UA NodeID YAML round-trip.
- `942f3fb` chunk 2 — Modbus proxy-session dry-run.
- `a509b2e` chunk 3 — CLI wire-up for 4 input providers.
- `62f8c6d` chunk 4 — ONYPHE input client (5th provider).
- `18e91bf` chunk 5 — SIP INVITE To-URI prefix allowlist.

**v1.10+ roadmap** (see `TODO-vNext.md`):
- SIP REGISTER AOR allowlist (toll-fraud twin of v1.9 chunk 5).
- Modbus per-(unit,fc,addr) structured YAML schema (closes
  v1.9 chunk 2 `--unit`/`--address-*` + `--emit-allow-file`
  incompatibility).
- OPC UA multi-node WriteRequest allowlist (chunk 1 checks
  first WriteValue only).
- OPC UA String/Guid/ByteString NodeID encoding (chunk 1 is
  numeric-only).
- OPC UA CallRequest per-object allowlist.
- BACnet per-object allowlist (ASN.1 BER parsing).
- CWMP offensive proxy (SOAP RPC allowlist).
- HTTP paths beyond `/` for pbxhttp fingerprint (vendor-
  specific `/admin/config.php`, `/webclient/`, `/ccmadmin/`).
- Match against String / Guid / ByteString NodeId encodings
  for OPC UA per-NodeId gate (v1.6 chunk 2 is numeric-only).
- Multi-node-per-WriteRequest allowlist (v1.6 chunk 2 only
  checks the first WriteValue).
- CallRequest per-object allowlist (OPC UA sibling of
  WriteRequest).
- VoIP-SIP dial backend subprocess.
- `dial batch --backend` CLI wiring.
- Audit daemon for cross-process JSONL.
- seccomp arg-level filtering.
- Runtime reload of the proxy listen allowlist (non-trivial
  because changing the allowlist changes PayloadHash which
  invalidates the confirm-token).

**Pushed on 2026-04-23**: everything. All tags v1.1.0 →
v1.8.0 on `origin/main`. Main at
`3286b5e docs: refresh manual / cheatsheet / README for
v1.8.0 community release`. Zero unpushed commits.

**GitHub Actions status**:
- Billing: spending limit reached / payment failed.
- All 8 release workflow runs (one per tag v1.0.0 → v1.8.0)
  aborted in ~30s with "job not started because payment has
  failed". No release artefacts were produced by CI.
- v1.8.0 artefacts (4 tarballs + 4 SBOMs + checksums.txt)
  built locally and uploaded manually via
  `gh release upload`.
- All 6 workflows (`ci`, `release`, `codeql`, `supply-chain`,
  `benchmarks`, `nightly`) gated to `workflow_dispatch:` only
  to stop accumulating billing failures.

**Historic commit list** (archived — all of these are now on
`origin/main`):

```
<v1.7.0>   65e5382 feat(v1.7 chunk 2): opcua/bacnet dry-run
           0f31d6e feat(v1.7 chunk 1): --emit-allow-file
<v1.6.0>   27fb616 docs(v1.6): close --allow-file + per-NodeId
           f76b3f2 feat(v1.6 chunk 2): opcua per-NodeId
           a5ee374 feat(v1.6 chunk 1): --allow-file YAML
<v1.5.0>   423d7a8 docs(v1.5): close proxy listen cycle
           1172eae feat(v1.5 chunk 2): extend proxy listen
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
