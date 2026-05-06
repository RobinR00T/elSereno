---
phase: v1.62-closed
status: v1.16-v1.27 published; v1.28-v1.62 tags pending push
last-updated: 2026-05-06
token-budget: 320
---

# Current state

**Phase**: **v1.62 cycle closed on `main`** (1 chunk +
close). Adds the dashboard scan-jobs panel on top of
the v1.58/59/60/61 stack. Operators submit, watch
state transitions, and cancel — without curl.
Two-tier polling cadence (2s active / 10s idle).
CSP nonce inheritance preserved. 2 new tests.

The dashboard scan-orchestration end-to-end is now
operator-facing: curl path + dashboard path both
work; v1.58 shell + v1.59 worker + v1.60 DB store +
v1.61 runner + v1.62 UI = full feature.

Snapshot: `.context/snapshots/v1.62.0-dashboard-scan-panel.md`.

**v1.62 chunks landed (in-flight)**:
- 1 `83e35f0` — dashboard.go scans-panel section +
  renderScans/submitScan/cancelScan + dashboard_test.go
  + INSTALL.md.

**v1.61 cycle (closed, snapshot available)**:
Real scan runner + serve --scan-store flag. 1 chunk
+ close: `08238d1`, `39f6036`. Snapshot:
`.context/snapshots/v1.61.0-scan-runner-serve-flag.md`.

**v1.60 cycle (closed, snapshot available)**:
Postgres-backed scan-job Store. 1 chunk + close:
`b51a1be`, `cd2e2de`. Snapshot:
`.context/snapshots/v1.60.0-scan-store-postgres.md`.

**v1.59 cycle (closed, snapshot available)**:
Scan-job Worker + JobRunner + Pool + Cancel. 1
chunk + close: `f03d099`, `4a8a4c6`. Snapshot:
`.context/snapshots/v1.59.0-scan-worker-pool-cancel.md`.

**v1.58 cycle (closed, snapshot available)**:
Dashboard scan-orchestration shell. Closes v1.50 F.
1 chunk + close: `d20ec3d`, `f9e3f4b`. Snapshot:
`.context/snapshots/v1.58.0-dashboard-scan-orchestration-shell.md`.

**v1.50 substantial-items batch is fully done**
(A=v1.52, B=v1.53, C=v1.54, D1=v1.55, D2=v1.56,
D3=v1.57, E=v1.51, F=v1.58). v1.59+ is forward
progress on the dashboard orchestration feature,
not carryover.

**v1.57 cycle (closed, snapshot available)**:
DLMS/COSEM offensive write-gated proxy on TCP/4059.
Three-tier gate (APDU + cosem + match strictness).
1 chunk + close: `b80546a`, `008f773`, `fc81d33`.
Snapshot: `.context/snapshots/v1.57.0-dlms-offensive-write.md`.

**v1.56 cycle (closed, snapshot available)**:
M-Bus over TCP offensive write-gated proxy on
TCP/10001. Two-tier gate (control field + per-(CI,
Address) tuple). 1 chunk + close: `c7820ca`,
`e420ec2`. Snapshot:
`.context/snapshots/v1.56.0-mbus-offensive-write.md`.

**v1.55 cycle (closed, snapshot available)**:
KNX offensive write-gated proxy on UDP/3671 + v1.21
service-type correctness fix. 1 chunk + close:
`9d688ac`, `9525afc`. Snapshot:
`.context/snapshots/v1.55.0-knx-offensive-write.md`.

**v1.54 cycle (closed, snapshot available)**:
Beckhoff TwinCAT ADS read-only fingerprint plugin on
TCP/48898. Plugin count: 28 → 29. 1 chunk + close:
`a57777f`, `e660bea`. Snapshot:
`.context/snapshots/v1.54.0-twincat-fingerprint.md`.

**v1.53 cycle (closed, snapshot available)**:
enip per-(class, instance, attribute) gating.
AllowlistHash separator 0xF2. 1 chunk + close:
`c08edfb`, `53af788`. Snapshot:
`.context/snapshots/v1.53.0-enip-per-attribute-gating.md`.

**v1.52 cycle (closed, snapshot available)**:
s7 per-(area, db, byte-address) gating for FuncWriteVar.
1 chunk + close: `829b769`, `8ef95de`. Snapshot:
`.context/snapshots/v1.52.0-s7-per-address-gating.md`.

**v1.51 cycle (closed, snapshot available)**:
MMS ACSE A-ASSOCIATE-REQUEST for IEC 61850-8-1 IED ID.
Confidence ~0.8 → ~0.95. 1 chunk + close: `4e13192`,
`98ea652`. Snapshot:
`.context/snapshots/v1.51.0-mms-acse-association.md`.

**v1.50 cycle (closed, snapshot available)**:
macOS sandbox_init(3) cgo-gated. Default release stays
pure-Go; new `make build-offensive-darwin-sandboxed`
opt-in. 1 chunk + close + STATE trim: `5ee142e`,
`b3e4d16`, `4346d57`. Snapshot:
`.context/snapshots/v1.50.0-macos-sandbox-init.md`.

**v1.41 → v1.49 cycles (closed; per-cycle snapshots in
`.context/snapshots/`):**
record/replay forensics + Linux packaging — tui --record
(v1.41), replay round-trip (v1.42), tui --rate (v1.43),
proxy replay --since/--until (v1.44), --json (v1.45),
--limit (v1.46), --tail (v1.47), --stats (v1.48). Linux
deb/rpm/apk via nfpm + hardened systemd units (v1.49).

**v1.32 → v1.40 cycles (closed; per-cycle snapshots in
`.context/snapshots/`):**
hygiene + tooling cycles — gosec marker migration (v1.32
+ v1.34), teatest TUI integration (v1.33), proxy listen
for 4 legacy-ICS protocols + recording (v1.35), dashboard
--input preview endpoint (v1.36), fingerprint
validate/capture verbs (v1.37 + v1.38), discover --hosts
(v1.39), plugins ports reverse-index (v1.40).

**v1.31 cycle (closed, snapshot available)**:
TUI `--input` parity with batch `scan` (all 8 kinds now
first-class on `tui --input KIND`). Input-parsing dispatcher
extracted to `cmd_input_parse.go`. 1 chunk + close: `689def2`,
`6d77468`. Snapshot:
`.context/snapshots/v1.31.0-tui-input-parity.md`.

**v1.30 cycle (closed, snapshot available)**:
Record-replay wire-up to 9 wire-aware gates + `--record FILE`
flag on `proxy listen` + `proxy replay` verb + TUI scan
launcher (`feeds.Interactive`) + audit-pane substring filter.
4 chunks + close: `1a9bc65`, `cab5b8c`, `4bd7a8e`, `15f954e`,
`df34f1c`. Snapshot:
`.context/snapshots/v1.30.0-record-wireup-tui-launcher-filter.md`.

**v1.29 cycle (closed, snapshot available)**:
TUI verb (bubbletea Model/View/Update + 4 modes:
interactive / replay / feed / watch) + mini build variant
(3-variant goreleaser: default + offensive + mini). 6 chunks +
close. Snapshot:
`.context/snapshots/v1.29.0-tui-and-mini-build.md`.

**v1.16 → v1.27 are published** on
https://github.com/RobinR00T/elSereno/releases. v1.28.0 +
v1.29.0 + v1.30.0 tags + releases pending push.

Snapshots:
- `.context/snapshots/v1.28.0-proconos-srtp-x21-recordwireup.md`
- `.context/snapshots/v1.29.0-tui-and-mini-build.md`
- `.context/snapshots/v1.30.0-record-wireup-tui-launcher-filter.md`

**v1.28 cycle (closed)**: ProConOS fingerprint (best-effort,
TCP/20547, confidence ~0.7) + GE-SRTP service-0x21 follow-up
(fw= suffix) + record-replay POC into pcworx + mms gates.
3 chunks + close: `7842351`, `bd70cb8`, `0242d68`, `cfa268b`.
Per-chunk detail in snapshot.

Per-cycle snapshots: see `.context/snapshots/v1.<N>.0-*.md`
for the v1.16 through v1.24 chunk-level detail. They're also
embedded in each tag's release notes on
https://github.com/RobinR00T/elSereno/releases.

**v1.16 → v1.21 cycles** (closed; per-cycle snapshots in
`.context/snapshots/v1.<N>.0-*.md`): CWMP / BACnet
refinements + token-generation cookies + SIGUSR1 reload +
observability + CSV export + audit API + legacy-ICS
fingerprint trios (FINS / SLMP / GE-SRTP / KNX / M-Bus /
DLMS).

**v1.15.0 published** as the latest GH release. 9 assets
(4 archives + 4 SBOMs + checksums.txt). Tag GPG-signed with
`ACE3B86BACACE7D6`. Loose-end closure cycle: CWMP
TransferComplete observer + discover --auto + STIX 2.1 +
audit flock + SIGHUP. Snapshot:
`.context/snapshots/v1.15.0-cwmp-discover-stix-flock-sighup.md`.

**v1.12 → v1.14 cycles** (closed): per-object/path scoping
across all 7 write-gates (v1.12), BACnet completion across
all 9 mutating services + CWMP polish + InternetDB bulk +
4th triage bucket (v1.13), IPv6 cross-cutting (v1.14). Per-
cycle snapshots in `.context/snapshots/`.

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
