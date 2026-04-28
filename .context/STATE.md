---
phase: v1.20-in-flight
status: v1.20 cycle closed on `main` (3 chunks, tag pending operator); v1.19 + v1.18 + v1.17 + v1.16 also closed
last-updated: 2026-04-28
token-budget: 300
---

# Current state

**Phase**: **v1.20 cycle closed on `main`** (3 chunks, tag
pending operator decision). Adds the legacy ICS fingerprint
trio: Omron FINS UDP, MELSEC SLMP TCP, GE-SRTP TCP. Default
build now registers **20 protocol plugins** (was 17). v1.19
also closed (3 chunks). v1.18 also closed (2 chunks). v1.17
also closed (5 chunks). v1.16 also closed (4 chunks).
v1.15.0 remains the latest published release on
https://github.com/RobinR00T/elSereno/releases/tag/v1.15.0.

**v1.20 chunks landed (in-flight)**:
- 1   `96c5453` — Omron FINS UDP fingerprint plugin (UDP/9600).
  CONTROLLER DATA READ (MRC=0x05 SRC=0x01) per OMRON CPU
  manual W421 §5.1/§5.4. Fail-closed UDP proxy. 12 wire +
  11 plugin tests.
- 2   `fcf5931` — MELSEC SLMP TCP fingerprint plugin (TCP/5007).
  READ CPU MODEL NAME (cmd 0x0101 sub 0x0000) per Mitsubishi
  Electric SLMP Reference Manual SH(NA)-080956ENG. Wire-layer
  write-ban (end code 0xC059). 9 wire + 11 plugin tests.
- 3   `8a89baa` — GE-SRTP TCP fingerprint plugin (TCP/18245).
  56-byte CONNECTION INIT mailbox reverse-engineered from
  Rapid7's nmap NSE script gesrtp-info + Conpot fixtures.
  Wire-layer write-ban (mailbox response with non-zero
  status byte). 6 wire + 7 plugin tests.

Snapshot:
`.context/snapshots/v1.20.0-legacy-ics-fingerprint-trio.md`.

**v1.19 chunks landed (in-flight)**:
- 1   Audit log API endpoint (`/api/v1/audit` +
  `/api/v1/audit/cadence`) + dashboard "Audit feed" panel
  with event_type/actor filters + payload excerpts.
  Tombstoned rows render as `[redacted]`. 6 tests.
- 2   `d2ebb0f` — Reload cadence dashboard panel surfaces
  the v1.17-chunk-5 `proxy_allowlist_reload` audit rows as a
  per-day text-based bar chart (last 7 days). Pure dashboard;
  reuses chunk-1's `/api/v1/audit/cadence`.
- 3   CWMP TransferComplete async firmware re-fetch
  (opt-in via `--verify-firmware-on-complete`). New
  `cwmp_firmware_verify` audit event + migration 00004.
  Goroutine-detached; closes the v1.16-chunk-1 loose end
  by detecting source-server firmware swaps post-flash.
  9 tests.

Snapshot:
`.context/snapshots/v1.19.0-observability-completion.md`.

**v1.18 chunks landed (in-flight, tag pending)**:
- 1   `cc157d4` — Dashboard CSV export from UI
  (`?format=csv` on `/api/v1/findings`, "Download CSV (top
  500)" link). 3 tests.
- 2   `1225312` — Dashboard diff between runs
  (`/api/v1/findings/diff?old=&new=`, new "Diff between runs"
  panel with new / resolved / persisting buckets matched by
  (target_id, protocol)). 9 tests.

Snapshot:
`.context/snapshots/v1.18.0-dashboard-csv-export-and-run-diff.md`.

**v1.17 chunks landed (in-flight)**:
- 1   `ed868af` — CWMP token-generation cookie + shared
  `--token-generation` flag promoted to session-flag
  registrar. Separator 0xFC. 7 tests.
- 2   `59ff0a2` — SIP token-generation cookie. Separator
  0xFC (below 0xFD fromDomains). 7 tests.
- 3   `(chunk 3)` — token-generation cookie roll-out across
  modbus / iax2 / pbxhttp / opcua. Completes cross-protocol
  parity (all 7 offensive write-gated proxies). Separators
  0xFC for modbus/iax2/pbxhttp, 0xFB for opcua. 20 tests.
- 4   `(chunk 4)` — SIGUSR1 in-process allow-file reload +
  atomic swap. New `--reload-allow-file` flag,
  `reloadableHandler` (atomic.Pointer wrapper), sidecar
  `<allow-file>.token` (0600) for fresh confirm-token. 11
  tests.
- 5   `02fef1e` — `proxy_allowlist_reload` audit event +
  migration 00003. Every SIGUSR1 firing emits a row with
  status / plugin / hash-prefixes / reason. 2 tests.

Snapshot:
`.context/snapshots/v1.17.0-token-generation-and-in-process-reload.md`.

**v1.16 chunks landed (in-flight, tag pending)**:
- 1   `33284c8` — CWMP TransferComplete authorisation
  cross-reference (closes v1.15 chunk-1 observer half).
  9 tests.
- 2   `83a4b69` — BACnet per-(type, instance) CreateObject
  scoping refinement (separator 0xF7). 9 tests.
- 3   `ed98c71` — BACnet per-(operation, type, instance)
  LifeSafetyOperation scoping refinement (separator 0xF6).
  9 tests.
- 4   `c3256da` — BACnet token-generation cookie (separator
  0xF5; foundation for in-process allow-file reload).
  7 tests.

Snapshot:
`.context/snapshots/v1.16.0-cwmp-bacnet-refinements-and-token-generation.md`.

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

**Shipped releases** (deep dives in
`.context/snapshots/v1.<N>.0-*.md`; ROADMAP.md highlights):
v1.0 → … → **v1.15** (latest published). v1.16 → v1.20 cycles
closed on `main`, tags pending operator.
**Counts now**:
- **20 protocol plugins** (default build): atg, atmodem, bacnet,
  banner, cwmp, dnp3, enip, finsudp, fox, gesrtp, hartip, iax2,
  iec104, modbus, opcua, pbxhttp, s7, sip, slmp, xot.
- 7 offensive write-gated proxies: modbus, opcua, sip, iax2,
  pbxhttp, bacnet, cwmp.
- 6 attack-surface input providers: shodan, censys, fofa,
  zoomeye, onyphe, internetdb (last no-key + bulk lookup).
- All 7 gates ship per-object / per-path scoping (v1.12 + v1.13).

**Deferred to v1.21+** (post-v1.20 backlog):
- macOS sandbox via `sandbox_init(3)`.
- 9 remaining legacy ICS protocols (PROFINET DCP / GOOSE / SV,
  CoDeSys, Red Lion, IEC 61850 MMS, KNX, M-Bus TCP, OPC UA
  HTTPS, DLMS/COSEM).
- Offensive plugins for the v1.20 trio (FINS / SLMP / SRTP).
- Big-picture: TUI (bubbletea), Windows support, OIDC + roles,
  record-&-replay proxy sessions.

**GitHub Actions status**: still gated to `workflow_dispatch:`
only (billing limit reached after v1.0.0). Local build flow
(goreleaser + syft + `gh release upload`) is the canonical
release path since v1.8. Cosign+SLSA+GHCR remain available
behind GHA billing restore.

**Bootstrap PAT**: still live. All v1.0–v1.15 work is shipped;
revoke now at
https://github.com/settings/personal-access-tokens.

**Repo**: `RobinR00T/elSereno`, **private**. Flip to public
is a pending operator decision.

**Live services** (preview-start / dev-db helper):
- dashboard 127.0.0.1:8787
- dev-db (pg 16) 127.0.0.1:5433 (via scripts/dev-db.sh)

## Open questions

- Operator: revoke the bootstrap PAT + rm ~/.elsereno/gh-token
  (v1.15.0 ships; session tokens unrevoked carry exfil risk).
- Repo public flip: still private; awaiting operator decision.
- Restore Actions billing: would re-enable cosign+SLSA+GHCR
  supply-chain layer. Cost vs value call.
