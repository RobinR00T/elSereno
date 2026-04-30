---
phase: v1.27-closed
status: v1.16 → v1.27 closed on `main`; v1.16-v1.26 published; v1.27 tag pending push
last-updated: 2026-04-30
token-budget: 300
---

# Current state

**Phase**: **v1.27 cycle closed on `main`** (4 chunks + close
commit). Seccomp arg-filter wire-up into Harvest+Dial profiles
+ pcworx and mms session-level offensive write-gates +
record/replay primitive. Default-build plugin count stays at
**27**. **9 offensive write-gates** (was 7): modbus, opcua, sip,
iax2, pbxhttp, bacnet, cwmp, **pcworx**, **mms**.

**v1.16 → v1.26 are published** on
https://github.com/RobinR00T/elSereno/releases. v1.27.0 tag +
release pending the close-commit push below.

Snapshot: `.context/snapshots/v1.27.0-seccomp-wireup-pcworx-mms-replay.md`.

**v1.27 chunks landed (closed)**:
- 1   `5533856` — wire seccomp arg-filter presets into Harvest
  (openat-no-write) + Dial (socket-deny-AF_PACKET-AF_NETLINK)
  profiles. ProfileExploit unchanged. 2 new tests.
- 2   `d4489f2` — pcworx offensive write-gate. Session-level
  (triple-confirm fence + audit row + byte relay; per-frame
  command gating defers to a future cycle once real-ILC
  test vectors are available). 9 tests.
- 3   `cec5ab9` — mms offensive write-gate. Same session-level
  shape; full ASN.1 BER walk through OSI session + ACSE +
  MMS PDUs is the v1.35 candidate. 9 tests.
- 4   `986f3c2` — record & replay primitive. NDJSON proxy-
  session capture with HeaderEvent + ChunkEvent. Wrap /
  WrapClient / WrapUpstream + Replay(ctx, path, cb). 8 tests.

Per-cycle snapshots: see `.context/snapshots/v1.<N>.0-*.md`
for the v1.16 through v1.24 chunk-level detail. They're also
embedded in each tag's release notes on
https://github.com/RobinR00T/elSereno/releases.

**v1.21 chunks landed (in-flight)**:
- 1   `9cd8700` — KNXnet/IP UDP/3671. 9 wire + 7 plugin tests.
- 2   `1f0f75b` — M-Bus over TCP/10001. 11 wire + 9 plugin tests.
- 3   `86e1034` — DLMS/COSEM TCP/4059. 7 wire + 9 plugin tests.
- 4   `3edaad1` — GE-SRTP model-hint refinement. 8 new tests.

Snapshot:
`.context/snapshots/v1.21.0-legacy-ics-trio-plus-srtp-refinement.md`.

**v1.20 cycle (3 chunks)**: Legacy-ICS fingerprint trio —
Omron FINS UDP/9600 (CONTROLLER DATA READ MRC=0x05 SRC=0x01),
MELSEC SLMP TCP/5007 (READ CPU MODEL NAME cmd 0x0101 sub
0x0000), GE-SRTP TCP/18245 (56-byte CONNECTION INIT mailbox
reverse-engineered from Rapid7 NSE + Conpot fixtures). 56
new tests.
Snapshot: `.context/snapshots/v1.20.0-legacy-ics-fingerprint-trio.md`.

**v1.19 cycle (3 chunks)**: Audit log API (`/api/v1/audit` +
`/api/v1/audit/cadence`) + dashboard "Audit feed" panel +
reload-cadence bar chart + CWMP TransferComplete async
firmware re-fetch (opt-in `--verify-firmware-on-complete`,
new `cwmp_firmware_verify` audit event, migration 00004).
15 tests.
Snapshot: `.context/snapshots/v1.19.0-observability-completion.md`.

**v1.18 cycle (2 chunks)**: Dashboard CSV export
(`?format=csv` on `/api/v1/findings`) + run-diff
(`/api/v1/findings/diff?old=&new=`). 12 tests.

Snapshot:
`.context/snapshots/v1.18.0-dashboard-csv-export-and-run-diff.md`.

**v1.17 cycle (5 chunks)**: Token-generation cookie parity across
all 7 offensive proxies (CWMP/SIP/Modbus/IAX2/pbxhttp/OPC UA) +
SIGUSR1 in-process allow-file reload (`reloadableHandler`,
`<allow-file>.token` sidecar 0600) + `proxy_allowlist_reload`
audit event (migration 00003). 47 tests.
Snapshot: `.context/snapshots/v1.17.0-token-generation-and-in-process-reload.md`.

**v1.16 cycle (4 chunks)**: CWMP TransferComplete authorisation
cross-reference + BACnet per-(type, instance) CreateObject + per-
(op, type, instance) LSO refinements + BACnet token-generation
cookie groundwork. 34 tests.
Snapshot: `.context/snapshots/v1.16.0-cwmp-bacnet-refinements-and-token-generation.md`.

**v1.15.0 published** on
https://github.com/RobinR00T/elSereno/releases/tag/v1.15.0.
9 release assets: 4 archives (darwin/linux × amd64/arm64) +
4 CycloneDX SBOMs + checksums.txt. Tag GPG-signed with
`ACE3B86BACACE7D6`. Loose-end closure cycle: CWMP
TransferComplete observer + `discover --auto <CIDR>` + STIX
2.1 export sink + audit cross-process flock + SIGHUP
reload-style exit.

**v1.15 chunks landed (released as v1.15.0)**:
- 1   `476b404` — CWMP TransferComplete observer. 6 tests.
- 2   `389ff5d` — `elsereno discover --auto <CIDR>` TCP-connect
  sweep. 9 tests.
- 3   `e205cd8` — STIX 2.1 export sink. 9 tests.
- 4   `dd92a39` — Audit chain cross-process merge via flock.
  2 tests.
- 5   `1264998` — SIGHUP reload-style graceful exit. 1 test.

Snapshot: `.context/snapshots/v1.15.0-cwmp-discover-stix-flock-sighup.md`.

v1.13 closes the BACnet leg of the per-RPC scoping work
started in v1.12 chunk 7. Theme: every BACnet mutating
service now has a wire-level per-target-or-state allowlist
(9 services × 8 hash separator bytes 0xF8–0xFF). Plus CWMP
polish (firmware verifier, RPC case-warning, over-TLS recipe),
InternetDB bulk lookup, and a 4th triage bucket (utility).

Snapshots:
- `.context/snapshots/v1.12.0-gates-tightening-and-inputs.md`
  (10-chunk v1.12 cycle).
- `.context/snapshots/v1.13.0-bacnet-completion-and-cwmp-polish.md`
  (13-chunk v1.13 cycle — full breakdown + per-chunk delta +
  hash separator allocation).

**v1.14 chunks landed (released as v1.14.0)**:
- 1   `8824885` — IPv6 foundation: `internal/netutil` package
  with `IsLoopbackHostPort` + `CanonicalHostPort` +
  `ParseAddrPort`. Replaces fragile substring-based loopback
  check in `cmd_serve.go`. 18 unit tests.
- 2   `0de0923` — Target canonicalisation across proxy listen +
  every dry-run command (sip/iax2/pbxhttp/modbus/opcua/cwmp +
  BACnet runner). 9 new tests.
- 3   `e0cae6f` — `scan --input internetdb:` IPv6 fixes (+
  missing dispatcher case from v1.13 chunk 1). 14 new tests.
- 4   `59e7d76` — IPv6 coverage tests for scope + dedupe paths
  (audit-only). 9 tests pin the contract.

Snapshot: `.context/snapshots/v1.14.0-ipv6-cross-cutting.md`.

**v1.13 chunks landed (released as v1.13.0)**:
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
- 8   `3f570e3` — BACnet CreateObject (svc 10) per-type
  allowlist + separate `AllowedCreateObjects` list.
- 9   `b51f488` — BACnet ReinitializeDevice (svc 20) per-state
  allowlist (0 coldstart..7 activate-changes).
- 10  `14a7451` — BACnet DeviceCommunicationControl (svc 17)
  per-state allowlist (0 enable / 1 disable / 2
  disableInitiation).
- 11  `6a10a70` — BACnet LifeSafetyOperation (svc 27)
  per-operation allowlist (0..9 incl. silence/reset/unsilence
  variants — fire-alarm safety guard).
- 12  `830ce02` — BACnet AtomicWriteFile (svc 7)
  per-File-instance allowlist (firmware blob vs log file
  separation).
- 13  `5952c55` — BACnet Add/RemoveListElement (svc 8/9)
  per-(object, property) allowlist (recipient lists,
  exception schedules — closes all 9 BACnet mutating
  services).

Sec gate fix from earlier: `b611f5c` swapped 18 `//nolint:gosec`
to native `// #nosec G<NNN>` markers — `make sec` now exit-0.

Read-only + protocol-flow RPCs (GetParameter*, Inform,
TransferComplete, Kicked, Fault) pasan siempre. Write-capable
RPCs (SetParameterValues, Reboot, FactoryReset, Download,
Upload, etc.) requieren allowlist explícito. Refusal es SOAP
Fault 9001 "Request denied" (TR-069 Annex A) + X-Elsereno-
Gate-Reason header.

GitHub Actions workflows quedaron desactivados (trigger
cambiado a `workflow_dispatch` only) después de que todos
fallaran con "payment failed / spending limit reached" — el
proyecto opera ahora en el tier gratuito de GitHub. Si en el
futuro se restaura billing, los workflows se pueden reactivar
editando el `on:` stanza en cada `.github/workflows/*.yml`
(los triggers originales quedan preservados en comentarios).

**Shipped releases** (deep dives in `.context/snapshots/`):
v1.0 → … → **v1.15** (latest published). v1.16 → v1.24 cycles
closed on `main`, tags pending operator push.

**Counts now**:
- **25 protocol plugins** (default build): atg, atmodem, bacnet,
  banner, codesys, cwmp, dlms, dnp3, enip, finsudp, fox, gesrtp,
  hartip, iax2, iec104, knxip, mbustcp, modbus, opcua, pbxhttp,
  redlion, s7, sip, slmp, xot.
- 7 offensive write-gated proxies: modbus, opcua, sip, iax2,
  pbxhttp, bacnet, cwmp. All ship per-object / per-path scoping.
- 6 attack-surface input providers: shodan, censys, fofa,
  zoomeye, onyphe, internetdb.
- 16 / 25 plugins publish a non-zero `cve_exposure` score
  (post v1.24 chunk 1).
- 25 / 25 plugins have engineering notes in
  `.context/protocols/` (post v1.24 chunk 2).

**Deferred to v1.25+**:
- cve_exposure for finsudp / slmp / gesrtp / knxip / mbustcp /
  dlms once their CVE histories harden.
- Offensive plugins for the v1.20 / v1.21 fingerprint trios.
- GE-SRTP service-0x21 follow-up.
- macOS sandbox via `sandbox_init(3)`.
- IEC 61850 MMS, OPC UA HTTPS, PROFINET (L2 with gopacket).
- Big-picture: TUI, Windows, OIDC + roles, record-&-replay.

**GitHub Actions**: gated to `workflow_dispatch:` (billing).
Local goreleaser + syft + `gh release upload` is the canonical
release path since v1.8.

**Operator-pending**:
- Push main + sign + push tags v1.16.0 → v1.24.0.
- Revoke bootstrap PAT, `rm ~/.elsereno/gh-token`.
- Repo public-flip decision.

**Live services**: dashboard 127.0.0.1:8787; dev-db (pg 16)
127.0.0.1:5433 via `scripts/dev-db.sh`.
