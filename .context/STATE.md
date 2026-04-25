---
phase: v1.12-closed
status: v1.12.0 ready to tag; gates tightening + input pagination cycle done
last-updated: 2026-04-25
token-budget: 300
---

# Current state

**Phase**: v1.12.0 ready to tag locally. Ten-chunk cycle that
closes every per-object / per-path / pagination carry-over
accumulated v1.6→v1.11. Each existing gate now scopes to a
specific identity, every input provider paginates, one new
no-key provider (internetdb) joins the input lineup, and CWMP
`Download` gets a per-firmware-URL gate. 7 offensive write-
gated proxies (unchanged), 6 attack-surface input providers
(up from 5).

See `.context/snapshots/v1.12.0-gates-tightening-and-inputs.md`
for the full per-chunk breakdown.

Read-only + protocol-flow RPCs (GetParameter*, Inform,
TransferComplete, Kicked, Fault) pasan siempre. Write-capable
RPCs (SetParameterValues, Reboot, FactoryReset, Download,
Upload, etc.) requieren allowlist explícito. Refusal es SOAP
Fault 9001 "Request denied" (TR-069 Annex A) + X-Elsereno-
Gate-Reason header.

v1.10.0 sigue publicado en GitHub Releases. v1.11.0 pendiente
de build local + gh release upload.

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
- **v1.11.0** (2026-04-24, local) — CWMP offensive proxy.
  SOAP RPC allowlist for ACS-CPE TR-069 traffic. 14 always-
  safe read-only + protocol-flow RPCs; operator allowlists
  write-capable ones (SetParameterValues, Reboot, Download,
  FactoryReset, etc.). Refusal is TR-069 Annex A SOAP Fault
  9001 "Request denied". 20 new tests. 7 offensive write-
  gated proxies in the default build (up from 6). See
  `.context/snapshots/v1.11.0-cwmp-offensive.md`.
- **v1.12.0** (2026-04-25, local) — gates tightening + input
  pagination. Ten-chunk cycle closing every per-object /
  per-path / pagination carry-over accumulated v1.6→v1.11.
  100 new tests. New: CWMP per-parameter-path + per-firmware-URL
  gates; OPC UA multi-node walks (numeric + String/GUID/
  ByteString) + per-CallMethod gate; Modbus structured writes
  YAML round-trip; SIP from-domain identity-spoof gate; BACnet
  per-WriteProperty (ASN.1 BER); pagination across 5 input
  providers; internetdb (6th, no-key). See
  `.context/snapshots/v1.12.0-gates-tightening-and-inputs.md`.
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

**v1.12 cycle — closed.** All 10 chunks landed (commits
`1a6cec3` → `9761eba`). See snapshot for the per-chunk
breakdown. Pending: tag + push + GitHub release upload.

After v1.12:
- SIP REGISTER AOR + CWMP SOAP RPC gates already landed (v1.10
  + v1.11).
- All gates offer per-object granularity.
- 6 attack-surface input providers (shodan / censys / fofa /
  zoomeye / onyphe / shodan-internetdb).

Deferred to v1.13+:
- CWMP RPC-name case-warning in dry-run.
- CWMP-over-TLS (:7548) operator recipe.
- SIGHUP reload of proxy listen allowlist (needs token/hash
  redesign).
- `elsereno discover --auto <CIDR>` scriptless nmap+probe.
- Triage bucket "utility" + dashboard diff-between-runs +
  severity filter + CSV export.
- seccomp arg-level filtering.
- macOS sandbox via `sandbox_init(3)`.
- Audit chain cross-process merge (flock).
- STIX 2.1 export.
- TUI bubbletea front-end.
- Record & replay proxy sessions.
- Windows support.
- Multi-user OIDC + roles.
- 12 legacy ICS protocols (PROFINET, CoDeSys, Omron FINS,
  MELSEC, Red Lion, GE-SRTP, IEC 61850 MMS, KNX, M-Bus TCP,
  OPC UA HTTPS, DLMS/COSEM, +1 more).

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

**Historic commit list**: see per-tag snapshots under
`.context/snapshots/` for per-cycle commit mapping. All tags
v1.0.0 → v1.11.0 are on `origin/main` with their respective
snapshots authoritative on what landed.

**Bootstrap PAT**: still live. Operator asked to keep it
until all v1.1/v1.2/v1.3/v1.4 work is pushed; revoke after at
https://github.com/settings/personal-access-tokens.

**Repo**: `RobinR00T/elSereno`, **private**. Flip to public
is a post-push operator decision.

**Live services** (preview-start / dev-db helper):
- dashboard 127.0.0.1:8787
- dev-db (pg 16) 127.0.0.1:5433 (via scripts/dev-db.sh)

## Open questions

- Operator: revoke the v1.8-era PAT + rm ~/.elsereno/gh-token
  once v1.12 ships (still live; session tokens unrevoked
  carry exfil risk).
- Repo public flip: still private. Post-v1.12 decision?
- Restore Actions billing: would re-enable cosign+SLSA+GHCR
  supply-chain layer. Cost vs value call.
