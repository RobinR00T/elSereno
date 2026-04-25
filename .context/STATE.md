---
phase: v1.13-in-flight
status: v1.12.0 released; 7 chunks of v1.13 landed on main, no tag yet
last-updated: 2026-04-25
token-budget: 300
---

# Current state

**Phase**: **v1.12.0 released** to GitHub
(https://github.com/RobinR00T/elSereno/releases/tag/v1.12.0).
**v1.13 cycle in flight on main** — 7 chunks landed since
v1.12.0 close, no tag yet (operator decides when to cut).

v1.13 is "post-v1.12 carry-over closure": each chunk fixes a
small gap or adds a missing CLI surface that v1.12 left for
later. Theme is incremental hardening + operator UX, not big
new features.

Snapshots:
- `.context/snapshots/v1.12.0-gates-tightening-and-inputs.md`
  (10-chunk v1.12 cycle, full breakdown).
- v1.13.0 snapshot will be written when the cycle is cut.

**v1.13 chunks landed (no tag yet)**:
- C   `c581a62` — TODO/TODO-vNext/man1 doc hygiene.
- 1   `781ee50` — InternetDB bulk lookup (`file:` + stdin).
- 2   `781ee50` — CWMP firmware pre-flight verifier
  (`elsereno-offensive write cwmp verify-firmware`).
- 3   `38dedff` — BACnet WPM (svc 16) per-object gate +
  depth-aware BER walker.
- 4   `861aa8d` — CWMP RPC-name case-warning in dry-run.
- 5   `861aa8d` — CWMP-over-TLS operator recipe (docs).
- 6   `20f6215` — Triage "utility" bucket (4th bucket).
- 7   `934c4f7` — BACnet DeleteObject (svc 11) per-target +
  separate `AllowedDeleteObjects` list.

Sec gate fix from earlier: `b611f5c` swapped 18 `//nolint:gosec`
to native `// #nosec G<NNN>` markers — `make sec` now exit-0.

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

**Counts now**:
- 17 protocol plugins (default build): atg, atmodem, bacnet,
  banner, cwmp, dnp3, enip, fox, hartip, iax2, iec104, modbus,
  opcua, pbxhttp, s7, sip, xot.
- 7 offensive write-gated proxies: modbus, opcua, sip, iax2,
  pbxhttp, bacnet, cwmp.
- 6 attack-surface input providers: shodan, censys, fofa,
  zoomeye, onyphe, internetdb (last is no-key + bulk lookup).
- All 7 gates ship per-object / per-path scoping (closed v1.12
  + v1.13).

**Per-cycle commits**: see `.context/snapshots/v1.<N>.0-*.md`
for the authoritative per-cycle commit mapping. All tags v1.0.0
→ v1.12.0 on `origin/main`.

**Deferred to v1.14+** (post-v1.13 backlog):
- IPv6 cross-cutting support (audit `netip.Addr` paths;
  bind/listen v6-aware; allowlist canonicalisation for `[::1]:
  port` literals). Operator-requested 2026-04-25; ~1 cycle.
- Per-object scoping for the rest of the BACnet mutating
  services (svc 10 / 17 / 20 / 27 / 7 / 8 / 9). v1.13 closed
  WPM (svc 16) + DeleteObject (svc 11).
- CWMP TransferComplete-side SHA-256 verification.
- SIGHUP reload of proxy listen allowlist.
- `elsereno discover --auto <CIDR>` scriptless nmap+probe.
- Audit chain cross-process merge (flock).
- macOS sandbox via `sandbox_init(3)`.
- 12 legacy ICS protocols.
- Big-picture: TUI, Windows, OIDC, record-&-replay, STIX 2.1.

**GitHub Actions status**: still gated to `workflow_dispatch:`
only (billing limit reached after v1.0.0). Local build flow
(goreleaser + syft + `gh release upload`) is the canonical
release path since v1.8. Cosign+SLSA+GHCR remain available
behind GHA billing restore.

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
