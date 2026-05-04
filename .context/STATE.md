---
phase: v1.38-closed
status: v1.16-v1.27 published; v1.28-v1.38 tags pending push
last-updated: 2026-05-04
token-budget: 320
---

# Current state

**Phase**: **v1.38 cycle closed on `main`** (1 chunk + close
commit). Adds `elsereno fingerprint capture` — the natural
companion to v1.37's `validate --file`. Opens a localhost
TCP listener, accepts one connection, drains the client's
bytes, writes them 0600 to a file. Operators with lab
access run `capture` in one window, point their PLC tool at
the port, then `validate --file` the resulting capture in a
follow-up command.

Snapshot: `.context/snapshots/v1.38.0-fingerprint-capture-verb.md`.

**v1.38 chunks landed (in-flight)**:
- 1 `9c44b82` — `newFingerprintCaptureCmd` +
  `runFingerprintCapture` + `acceptWithCtx` helper +
  4 tests (HappyPath, MissingOutput, TimeoutOnIdleListener,
  ClientClosesEmpty).

**v1.37 cycle (closed, snapshot available)**:
fingerprint validation CLI verb (operator-facing harness for
the v1.28 ProConOS + GE-SRTP confidence-0.7 carryover).
1 chunk + close: `cfe268c`, `a2f2492`. Snapshot:
`.context/snapshots/v1.37.0-fingerprint-validate-verb.md`.

**v1.36 cycle (closed, snapshot available)**:
Dashboard --input parity (preview endpoint). New
`GET /api/v1/inputs/preview` endpoint backed by
`internal/inputs/preview` package; read-only verification
of list:/nmap:/stdin input files from inside the dashboard.
1 chunk + close: `d8d40e3`, `f8e1303`. Snapshot:
`.context/snapshots/v1.36.0-dashboard-input-preview.md`.

**v1.35 cycle (closed, snapshot available)**:
proxy listen --plugin for 4 legacy-ICS plugins (pcworx +
mms + enip + s7) + recording. 1 chunk + close: `23aa50c`,
`36e3e2c`. Snapshot:
`.context/snapshots/v1.35.0-proxy-listen-legacy-ics.md`.

**v1.34 cycle (closed, snapshot available)**:
Tree-wide //nolint:gosec → // #nosec G<NNN> sweep (76
markers across 49 files; PITF-030 enforced tree-wide).
Side-fix: comment-eats-statement bug in enip/write.go.
1 chunk + close: `75cbcf5`, `801a12d`. Snapshot:
`.context/snapshots/v1.34.0-tree-wide-gosec-hygiene.md`.

**v1.33 cycle (closed, snapshot available)**:
teatest program-level integration tests for the TUI runner
(closes v1.30+v1.31 carryover). 10 cases in
`internal/tui/program_test.go`. 1 chunk + close: `29ecaf4`,
`f69e4bc`. Snapshot:
`.context/snapshots/v1.33.0-teatest-tui-integration.md`.

**v1.32 cycle (closed, snapshot available)**:
Hygiene-only: completes the b611f5c migration for the
cmd/elsereno/ subtree (10 `//nolint:gosec` → `// #nosec
G<NNN>`). Wider tree (~65 more markers) is its own
follow-up. 1 chunk + close: `f4e2464`, `a9e29ff`. Snapshot:
`.context/snapshots/v1.32.0-cmd-gosec-marker-hygiene.md`.

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

**v1.14 cycle (4 chunks)**: IPv6 cross-cutting — internal/netutil
package + target canonicalisation across proxies/dry-runs +
internetdb IPv6 fixes + scope/dedupe IPv6 coverage. 50 tests.
Snapshot: `.context/snapshots/v1.14.0-ipv6-cross-cutting.md`.

**v1.13 cycle (13 chunks)**: BACnet completion (per-target /
per-state / per-operation / per-instance / per-(object,property)
allowlists for the 9 mutating services) + CWMP polish (firmware
pre-flight, RPC case-warning, over-TLS recipe) + InternetDB bulk
lookup + 4th triage bucket. Per-chunk detail in snapshot.

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
