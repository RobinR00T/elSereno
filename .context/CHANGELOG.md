---
phase: any
status: living
last-updated: 2026-05-03
---

# Context changelog

One-liner per significant change to `.context/` or the codebase.

- 2026-05-05 — v1.55 (chunk 1) — **KNX offensive write-
  gated proxy on UDP/3671.** Closes v1.32+ D1.
  Three-tier gate (service-type / APCI / group-address)
  with mask semantics. Plus a v1.21 service-type
  correctness fix (DESCRIPTION_REQUEST 0x0204 → 0x0203
  per KNX Standard). 24 tests. Snapshot:
  `.context/snapshots/v1.55.0-knx-offensive-write.md`.

- 2026-05-05 — v1.54 (chunk 1) — **Beckhoff TwinCAT ADS
  fingerprint plugin (TCP/48898).** Closes v1.32+ C.
  AMS/TCP framing + AMS routing header +
  ReadDeviceInfo. Plugin count 28 → 29. 8 tests.
  Snapshot:
  `.context/snapshots/v1.54.0-twincat-fingerprint.md`.

- 2026-05-05 — v1.53 (chunk 1) — **enip per-(class,
  instance, attribute) gating for SendRRData /
  SendUnitData.** Closes v1.32+ B. CIP MR EPATH parser +
  AllowedAttribute (3 match strictnesses) +
  AllowlistHash dimension (separator 0xF2). 12 tests.
  Snapshot:
  `.context/snapshots/v1.53.0-enip-per-attribute-gating.md`.

- 2026-05-05 — v1.52 (chunk 1) — **s7 per-(area, db,
  byte-address) gating for FuncWriteVar.** Closes the
  v1.32+ A carryover. Wire parser + AllowedWriteItem
  + AllowlistHash per-item dimension (separator 0xF1).
  Empty list = v1.27 backward-compat. 11 new tests.
  Snapshot:
  `.context/snapshots/v1.52.0-s7-per-address-gating.md`.

- 2026-05-05 — v1.51 (chunk 1) — **MMS ACSE
  A-ASSOCIATE-REQUEST.** Closes the v1.32+ E carryover.
  Hand-coded static OSI/Presentation/ACSE AARQ + OID-
  pattern AARE scan. MMS plugin confidence ~0.8 → ~0.95
  for IEC 61850-8-1 IEDs. 6 new tests. Snapshot:
  `.context/snapshots/v1.51.0-mms-acse-association.md`.

- 2026-05-05 — v1.50 (chunk 1) — **macOS `sandbox_init(3)`
  cgo-gated.** Closes the long-standing G carryover
  ("macOS sandbox via cgo break"). Opt-in:
  `make build-offensive-darwin-sandboxed`. Default
  release stays pure-Go. 3 .sb Scheme profiles
  (exploit/harvest/dial) + 3 tests + INSTALL.md update.
  Snapshot:
  `.context/snapshots/v1.50.0-macos-sandbox-init.md`.

- 2026-05-05 — v1.49 (chunk 1) — **Linux distribution
  packaging.** deb/rpm/apk via nfpm (3 variants × 3
  formats × 2 archs = 18 packages per release).
  Hardened systemd units for serve + audit serve.
  preinstall/postinstall scripts. New INSTALL.md
  (~250 lines, both platforms with feature matrix +
  pros/cons). Standing instruction: every cycle from
  here updates both macOS+Linux artefacts and the
  platform-specific docs. Snapshot:
  `.context/snapshots/v1.49.0-linux-distribution-packaging.md`.

- 2026-05-05 — v1.48 (chunk 1) — **`proxy replay
  --stats`** summary mode: per-direction chunk count +
  total bytes + time range. No per-chunk lines. Mutually
  exclusive with --limit/--tail/--json. validateMutex-
  Flags consolidator. 3 tests. Snapshot:
  `.context/snapshots/v1.48.0-proxy-replay-stats.md`.

- 2026-05-05 — v1.47 (chunk 1) — **`proxy replay
  --tail N`** symmetric counterpart to --limit; emits
  last N matching chunks via ring buffer (memory caps
  at N regardless of capture size). --limit / --tail
  mutually exclusive at parse time. 3 tests. Snapshot:
  `.context/snapshots/v1.47.0-proxy-replay-tail.md`.

- 2026-05-05 — v1.46 (chunk 1) — **`proxy replay
  --limit N`** caps output at N matching chunks. Applied
  AFTER --dir/--since/--until filters. errReplay-
  LimitReached sentinel ends the file walker early.
  chunkPassesFilters helper extracted (gocyclo). 3 tests.
  Snapshot:
  `.context/snapshots/v1.46.0-proxy-replay-limit.md`.

- 2026-05-05 — v1.45 (chunk 1) — **`proxy replay --json`**
  machine-readable output. One ChunkEvent per line, no
  header preamble. Composes with v1.44 filters. Side fix:
  dispatcher now skips DirHeader (was producing a phantom
  "c→u  0B" line via formatter's default arrow). 2 new
  tests + 1 adjusted. Snapshot:
  `.context/snapshots/v1.45.0-proxy-replay-json.md`.

- 2026-05-05 — v1.44 (chunk 1) — **`proxy replay
  --since/--until`** time-window forensics. RFC3339Nano
  bounds, inclusive, optional either-side. timeWindow
  short-circuits to true on no-flags so the cost is zero
  for the common case. 4 tests. Snapshot:
  `.context/snapshots/v1.44.0-proxy-replay-time-window.md`.

- 2026-05-05 — v1.43 (chunk 1) — **`tui --rate N`** for
  slow-motion playback. Plumbs the existing Rate field via
  a CLI flag. 3 tests. Snapshot:
  `.context/snapshots/v1.43.0-tui-rate-flag.md`.

- 2026-05-04 — v1.42 (chunk 1) — **replay/record round-trip
  closed.** `feeds.Replay` now reads both `ndjson:v1`
  (legacy scan-output) AND the v1.41
  `elsereno-tui-record/v1` schemas. Workflow:
  `tui --replay scan.ndjson --record session.ndjson;
   tui --replay session.ndjson` (full loop). Type-tagged
  dispatch + forward-compat for unknown types. 8 tests.
  Snapshot:
  `.context/snapshots/v1.42.0-replay-record-roundtrip.md`.

- 2026-05-04 — v1.41 (chunk 1) — **`tui --record
  FILE.ndjson`.** Symmetric counterpart to v1.29-chunk-3's
  --replay. Tees every model-bound tea.Msg onto an NDJSON
  file (`elsereno-tui-record/v1` schema). Best-effort —
  encode errors silenced so the TUI doesn't die for an
  unwritable file. Adds `RunOpts` + `RunWithOpts` (Run
  preserved as back-compat shim). 8 tests. Snapshot:
  `.context/snapshots/v1.41.0-tui-record-session.md`.

- 2026-05-04 — v1.40 (chunk 1) — **`plugins ports` reverse
  index.** Maps port → [plugins] for "which plugin claims
  502?" lookups. Plain-text default + --json. Pin'd
  shared-port colocation (mms + s7 on 102) in tests.
  4 tests. Snapshot:
  `.context/snapshots/v1.40.0-plugins-ports-reverse-index.md`.

- 2026-05-04 — v1.39 (chunk 1) — **`discover --hosts <file>`.**
  Natural counterpart to v1.15-chunk-2's `--auto <CIDR>`.
  Accepts one IP per line, comments + blanks + host:port-
  strip + IPv6 support, --max-hosts cap. 7 tests. Snapshot:
  `.context/snapshots/v1.39.0-discover-hosts-list.md`.

- 2026-05-04 — v1.38 (chunk 1) — **`fingerprint capture`
  verb.** Natural companion to v1.37's `validate --file`:
  opens a localhost TCP listener, accepts one connection,
  drains the bytes, writes 0600. Operators capture in one
  window, validate in another. Refuses 0-byte writes. 4
  tests + 2 helpers (waitForListenPort, dialTimeout).
  Snapshot:
  `.context/snapshots/v1.38.0-fingerprint-capture-verb.md`.

- 2026-05-04 — v1.37 (chunk 1) — **Fingerprint validation
  CLI verb.** Closes the v1.28-chunks-1+2 carryover. New
  `elsereno fingerprint validate --plugin <name>
  (--file|--hex)` verb spins up a localhost responder that
  replies with operator-supplied bytes + drives Probe
  through it. Works for every registered plugin. 13 tests
  including a table-driven across proconos + gesrtp.
  Snapshot:
  `.context/snapshots/v1.37.0-fingerprint-validate-verb.md`.

- 2026-05-04 — v1.36 (chunk 1) — **Dashboard --input
  parity (preview endpoint).** Closes the v1.31 carryover.
  New `GET /api/v1/inputs/preview` endpoint backed by the
  new `internal/inputs/preview` package. Read-only —
  verifies a list:/nmap:/stdin file from inside the
  dashboard before triggering a CLI scan against it.
  Provider kinds excluded (need creds + rate-limit tuning
  the dashboard intentionally doesn't carry). 14 tests +
  OpenAPI spec regeneration. Snapshot:
  `.context/snapshots/v1.36.0-dashboard-input-preview.md`.

- 2026-05-04 — v1.35 (chunk 1) — **proxy listen --plugin
  pcworx|mms|enip|s7 + recording.** Closes the v1.30
  carryover. Wires the 4 legacy-ICS plugins (which already
  had Recorder fields from v1.28 chunk 3 / v1.30 chunk 1)
  as new --plugin values on `proxy listen`. New flags:
  --intent (pcworx + mms), --cip-command (enip), --s7-fc
  (s7). 13 dispatcher tests including the
  TestAttachRecorder_AllSupportedHandlers invariant pin.
  Snapshot:
  `.context/snapshots/v1.35.0-proxy-listen-legacy-ics.md`.

- 2026-05-03 — v1.34 (chunk 1) — **Tree-wide gosec marker
  hygiene.** Completes the b611f5c migration: 76 `//nolint:
  gosec` directives across 49 files in internal/**,
  offensive/** swapped to `// #nosec G<NNN>` native form.
  Side-fix: corrected a pre-existing comment-eats-statement
  bug in offensive/write/enip/write.go line 148 (directive on
  same physical line as tabbed code, silently breaking
  SendRRData body append). PITF-030 now enforced tree-wide.
  Snapshot:
  `.context/snapshots/v1.34.0-tree-wide-gosec-hygiene.md`.

- 2026-05-03 — v1.33 (chunk 1) — **teatest program-level
  integration tests for TUI runner.** Closes the v1.30+v1.31
  carryover. `internal/tui/program_test.go` drives the
  bubbletea program through `teatest`; 10 cases cover
  quit-on-q/ctrl+c, header+4-pane render, FindingMsg/AuditMsg
  fold, full filter-edit cycle, Tab focus cycle, severity-band
  rendering, terminal-too-small fallback, clean-output drain.
  +1 indirect dep (teatest, test-only) + a colorprofile
  minor bump on the lipgloss-linked path. Mini binary
  unchanged. Snapshot:
  `.context/snapshots/v1.33.0-teatest-tui-integration.md`.

- 2026-05-03 — v1.32 (chunk 1) — **cmd/elsereno gosec marker
  hygiene.** Swaps 10 remaining `//nolint:gosec` directives
  to `// #nosec G<NNN>` native form (PITF-030 / b611f5c
  convention). Composite case in cmd_doctor.go split. Wider
  tree (~65 markers across internal/protocols/**, offensive/**,
  internal/audit/**) intentionally untouched — coexists with
  convention since b611f5c, `make sec` exit 0 throughout.
  Snapshot:
  `.context/snapshots/v1.32.0-cmd-gosec-marker-hygiene.md`.

- 2026-05-03 — v1.31 (chunk 1) — **TUI `--input` parity with
  batch `scan`.** Closes the v1.30-chunk-3 carryover. The 7
  input kinds the batch verb supports (nmap:, stdin, shodan:,
  censys:, fofa:, zoomeye:, onyphe:, internetdb:) are now
  first-class on `elsereno tui --input KIND`. Input-parsing
  dispatcher extracted to `cmd_input_parse.go` so future
  input kinds land in one place rather than diverging across
  cmd_scan and cmd_tui. New `--api-creds-file` flag on `tui`
  mirroring `scan`. 7 dispatcher tests. Snapshot:
  `.context/snapshots/v1.31.0-tui-input-parity.md`.

- 2026-05-02 — v1.30 (chunks 1-4) — **Record-replay wire-up to
  9 wire-aware gates + TUI scan launcher + audit filter.**
  Closes the v1.28-chunk-3 deferral by extending the optional
  `Recorder *replay.Recorder` field from the 2 session-level
  POC gates to the 9 wire-aware gates (sip, iax2, pbxhttp,
  modbus, opcua, bacnet, cwmp, enip, s7). Operator-facing
  `--record FILE` on `proxy listen` + new `proxy replay FILE`
  sub-verb. Closes the v1.29-chunk-2 deferral by replacing
  `feeds.Empty` with `feeds.Interactive` running
  `scanner.Scanner` inside the TUI (`--input list:FILE`).
  TUI audit-pane substring filter (`/`-edit). 19 new tests.
  Snapshot:
  `.context/snapshots/v1.30.0-record-wireup-tui-launcher-filter.md`.

- 2026-05-01 — v1.29 (chunks 1-6) — **TUI verb (`elsereno tui`) +
  mini build variant.** Bubbletea Model/View/Update + 4-pane
  layout (findings / triage / audit / scan); 4 modes via
  flags (interactive / replay / feed / watch). Mini variant
  excludes the bubbletea/lipgloss/web stack; goreleaser ships
  3 archives per OS/arch. New `.context/tui.md` (architecture +
  key bindings + wire formats + build-tag matrix). 44 unit
  tests across `internal/tui/` + `internal/tui/feeds/`.

- 2026-04-29 — v1.24 (chunk 2) — **Engineering notes for the
  5 missing plugins in `.context/protocols/`.** Plugin coverage
  in the engineering-notes directory was 20 of 25 after v1.22
  (cwmp / opcua / sip / iax2 / pbxhttp had no notes despite
  being shipped years ago). This chunk fills them in with the
  same shape as the other 20: TL;DR + spec references + wire
  format + fingerprint strategy + read operations + write/dial
  ops + REPL plan + proxy hooks + scoring contribution +
  sentinel cases. Each note's last-updated timestamp + status
  is current; cwmp.md notes the v1.16/v1.17/v1.19 chunk
  history (TransferComplete observer + async firmware
  re-fetch); opcua.md notes the v1.6/v1.12/v1.17 chunk
  history (per-NodeId + per-CallMethod gating + token-
  generation cookie). All 25 plugins now have engineering
  notes.

- 2026-04-29 — v1.24 (chunk 1) — **CVE-exposure expansion to
  7 more plugins.** Closes the cve_exposure non-zero coverage
  gap on the remaining ICS + PBX plugins (was 9 of 25 after
  v1.23; is now 16 of 25). New values:
  - s7: 14 (CVE-2014-2249 stack overflow + CVE-2016-4785
    auth bypass + CVE-2018-13815 PLC crash + Stuxnet-era
    CVE-2010-2772 — broadest CVE surface in the ICS plugin
    set, reflects Siemens PLC market share).
  - fox: 13 (CVE-2012-3024 Niagara hardcoded creds,
    CVE-2015-2916 directory traversal, CVE-2017-16744 Niagara
    AX — Tridium dominates large-scale BMS).
  - sip: 12 (Asterisk SIP CVE-2009-1207 + decades of
    follow-ups, Cisco SPA + UC CVE-2017-3881, FreeSWITCH
    CVE-2021-33611, 3CX CVE-2023-29059 supply-chain).
  - enip: 11 (CVE-2017-7898 + CVE-2018-19009 + CVE-2020-
    12029 Rockwell stack + CVE-2021-22681 hardcoded crypto).
  - pbxhttp: 11 (FreePBX RCE family CVE-2014-7235 + 2019-
    19006 + 2020-25822, Asterisk Manager web CVE-2017-9358,
    3CX 2023-29059, Mitel MiCollab CVE-2024-41713).
  - iax2: 9 (Asterisk IAX2 family CVE-2007-3764 + CVE-2008-
    3263 + CVE-2009-3727 + CVE-2014-9374).
  - modbus: 9 (CVE-2015-1015 Schneider Modicon DoS, CVE-
    2017-9853 M340/M580 stack, CVE-2018-7240 Premium /
    Quantum, CVE-2021-22779 auth bypass — vendor stacks atop
    the auth-free protocol).
  Combined v1.22 + v1.23 + v1.24: 16 of 25 plugins now
  publish a non-zero cve_exposure score (was 0 at v1.21).
  Remaining plugins without cve_exposure: atmodem, banner
  (meta), xot — all have either no notable CVEs or n/a.

- 2026-04-29 — v1.23 (chunk 2) — **Banner dictionary
  expansion: 21 new vendor patterns.** Vendor count climbs
  from 9 (v1.0 baseline) to 30 across three categories:
  industrial controller / HMI / RTU vendors (Siemens
  SIMATIC + RUGGEDCOM, Rockwell Automation / Allen-Bradley,
  Schneider Modicon, ABB AC500 / Robotics, WAGO PFC, Beckhoff
  CX/BX, Phoenix Contact AXC / ME-PLC, Hirschmann / Belden,
  Westermo, Advantech EKI, Sealevel, Honeywell Experion,
  Johnson Controls Metasys, Tridium Niagara), and
  network-gear adjacent to ICS (Cisco IOS / IOS-XE, MikroTik
  RouterOS, Ubiquiti EdgeOS / UniFi, pfSense / OPNsense,
  Dropbear SSH, RomPager). Order-sensitivity guarded by a
  dedicated test asserting that a banner referencing both
  SIMATIC and Cisco IOS matches Siemens first (most-specific
  rule wins). 24 new test cases bring the banner-dictionary
  test count from 8 to 32 — every new vendor has at least
  one exemplar banner string.

- 2026-04-29 — v1.23 (chunk 1) — **CVE-exposure factor
  expansion for 7 plugins.** Set non-zero cve_exposure values
  on plugins with well-documented CVE families (previously all
  zero except codesys=10 + redlion=5 from v1.22). New values
  with rationale:
  - cwmp: 15 (CVE-2014-9222 Misfortune Cookie / RomPager +
    TR-064 NewNTPServer command-injection family — broad legacy
    CPE exposure on the same port 7547 ACS endpoint).
  - dnp3: 12 (CVE-2013-2825 CRC bypass + CVE-2013-2829 TCP
    frame stack overflow + CVE-2014-5410 Triangle MicroWorks
    DNP3 implementation flaws).
  - iec104: 10 (CVE-2015-7906 SIPROTEC + CVE-2017-12089 SICAM
    PAS + CVE-2019-13548 SICAM PAS — substation automation
    family). Pushes scoring into highest severity bucket on
    positive ID since impact_class is already 90.
  - bacnet: 8 (CVE-2018-10628 BAS auth bypass + CVE-2019-12480
    Wago I/O System + CVE-2020-12511 Schneider U.motion).
  - opcua: 8 (CVE-2017-12069 Siemens OPC UA + CVE-2019-10936
    open62541 cert validation + CVE-2022-29862 Unified
    Automation OPC UA C++ DoS).
  - hartip: 7 (CVE-2014-7494 Honeywell XYR + CVE-2015-7905
    Yokogawa STARDOM + CVE-2019-9869 Phoenix Contact HART-IP).
  - atg: 6 (CVE-2017-14432/14433 Veeder-Root TLS-450 +
    CVE-2018-5443 — gas-station-tank-gauge family).
  Each value cites specific CVEs in code comments so future
  maintainers can validate. cve_exposure remains weighted at
  0.10 in `scoreFor`. No behaviour changes beyond scoring.
  All affected plugin tests still pass; `make ci` green.

- 2026-04-29 — v1.22 (chunk 4) — **Fuzz coverage for v1.20 +
  v1.21 + v1.22 wire packages + finsudp trimASCII fix.** Added
  Fuzz* targets to all 8 new wire packages: finsudp, slmp,
  gesrtp, knxip, mbustcp, dlms, codesys, redlion. Each has a
  parser fuzz (asserts no panic + per-package contract on
  success) and a builder fuzz (asserts frame-length stability
  across input). Doubles the in-tree Fuzz* target count from
  6 to 14 — every from-scratch wire parser shipped since v1.20
  is now under fuzz.

  **Fuzz found a real bug** in finsudp's `trimASCII` —
  exact duplicate of the slmp bug fixed in v1.21 chunk 2 but
  shipped earlier (v1.20 chunk 1) and missed at the time.
  trimASCII used the order-dependent two-call form
  `strings.TrimRight(strings.TrimRight(s, "\x00"), " ")` which
  leaves trailing NULs when padding interleaves `0x00` and
  ` `. Fixed with the single-pass cutset
  `strings.TrimRight(string(b), "\x00 ")`. Regression seed
  preserved at testdata/fuzz/FuzzParseControllerDataRead/.
  No public release ever shipped the buggy v1.20 finsudp —
  v1.20 cycle is closed on `main` with tag pending operator.

- 2026-04-29 — v1.22 (chunk 3) — **Red Lion Crimson / RLN
  fingerprint plugin on TCP/789.** Banner-substring fingerprint
  for Red Lion's G3 / G3 Kadet / Graphite / FlexEdge / DA-50N
  HMI families and the post-2010-acquisition Sixnet RTU line.
  Plugin connects, reads any unsolicited banner (Crimson
  firmware typically announces itself on connect), falls back
  to a 3-byte zero hello if nothing arrives in IOTimeout/2,
  then classifies by 12 canonical banner substrings (Red Lion
  Controls / Red Lion / Crimson 3 / CRIMSON 3 / Crimson 2 /
  FlexEdge / Graphite / DA-50N / DA50N / G3 Kadet / G3 HMI /
  Sixnet) ordered most-specific first. Fail-closed proxy.
  Score factors{protocol_risk:75, exposure:75, auth_state:85,
  capability:30→70 on Red Lion reply, impact_class:70,
  cve_exposure:5}. cve_exposure 5 reflects ICSA-21-103-01
  (hardcoded crypto key) + ICSA-22-088-01 (path traversal). 25
  protocol plugins now register in the default build (24 → 25);
  6 wire tests + 7 plugin tests; `make ci` green.

- 2026-04-28 — v1.22 (chunk 2) — **CoDeSys V3 TCP fingerprint
  plugin on TCP/1217.** Continues the legacy-ICS roll-out from
  v1.20 + v1.21. Sends the 4-byte BlockDriver magic hello
  (0xCD 0xCD 0xCD 0xCD) and classifies the response by either
  the magic echo or canonical banner substring (CoDeSys /
  CODESYS / 3S-Smart / 3S-CoDeSys / CmpHostname / CmpAppBP /
  CmpRuntime). Reverse-engineered from libcodesys-py +
  codesys-rs + ICS-CERT advisory captures (ICSA-12-242-01 /
  19-080-01 / 21-014-04). Fail-closed proxy — proprietary
  Layer-3/4/7 APDU stack out of scope for chunk 2. Score
  factors{protocol_risk:80, exposure:75, auth_state:85,
  capability:30→70 on CoDeSys reply, impact_class:75,
  cve_exposure:10}. **First plugin to set cve_exposure
  non-zero** — reflects the well-known CVE family. 24 protocol
  plugins now register in the default build (23 → 24); 6 wire
  tests + 7 plugin tests; `make ci` green.

- 2026-04-28 — v1.22 (chunk 1) — **CI hygiene: fuzz-flake retry
  + explicit timeout in `scripts/run-fuzz.sh`.** Closes a
  pre-existing intermittent failure where `xot/wire
  FuzzParseHeader` and `render FuzzSafeBytes` would report
  "context deadline exceeded" at the end of their fuzztime
  budget on macOS — Go's fuzz worker scheduling occasionally
  races GC / GOMAXPROCS pressure and reports a deadline even
  though no real fuzz crash occurred. Two fixes: (1) explicit
  `-timeout` 4× the fuzz duration (capped at 60s minimum),
  giving Go's per-test default 10m headroom no chance to fight
  short fuzz budgets; (2) up to MAX_ATTEMPTS=3 retries per
  target when the failure pattern is "context deadline
  exceeded" specifically — genuine fuzz failures (panic / fail
  line not matching the deadline pattern) short-circuit the
  retry loop. Smoke-test pass on all 6 Fuzz* targets with both
  5s and 30s budgets.

- 2026-04-28 — v1.21 (chunk 4) — **GE-SRTP model-hint extraction
  refinement.** Refines the v1.20 chunk 3 connection-init-only
  fingerprint by scanning the 56-byte mailbox response payload
  for embedded GE PLC family strings (PACSystems / IC693 / IC695
  / IC697 / IC200 / RX3i / RX7i) and folding the matched hint
  into the finding note. New `wire.ExtractModelHint` greedy-
  matches printable-ASCII runs (letters / digits / dash /
  underscore) starting on uppercase boundaries; rejects runs
  shorter than 5 chars and runs without a canonical-prefix
  match. Plugin's `buildFinding` now takes a `modelHint string`
  parameter — when non-empty, capability lifts from 70 to 75 (so
  gesrtp now matches finsudp / slmp on positive-id capability,
  with a graceful 70-floor when no hint is recoverable). 7 new
  wire tests cover all canonical prefixes, no-match cases (nil /
  empty / all-zero / lowercase / wrong-vendor), first-wins
  ordering, and stops-at-non-printable. New plugin test asserts
  the capability lift on a 56-byte response carrying an
  IC695CPE330 hint at offset 16. `make ci` green; no API
  changes; no migration.

- 2026-04-28 — v1.21 (chunk 3) — **DLMS/COSEM TCP fingerprint
  plugin on TCP/4059.** Third chunk of v1.21. Sends a 37-byte
  DLMS-wrapper-framed AARQ probe (8-byte wrapper + 29-byte
  canonical minimal AARQ APDU referencing OID 2.16.756.5.8.1.1
  LN-no-ciphering) per IEC 62056-46 §8.4 + IEC 62056-53.
  Classifies by wrapper version (0x0001) + AARE tag (0x61).
  Wrapper-only responses also count as positive identification
  (the server speaks DLMS-wrapper but rejected our AARQ —
  common with HLS-locked deployments). ProxyHandler is
  wire-layer write-ban: reads the wrapper header + APDU body,
  replies with a 16-byte wrapper-framed AARE (0xA2 0x03 0x02
  0x01 0x01 = associate-result rejected-permanent) padded with a
  BER end-of-content byte. Score factors{protocol_risk:75,
  exposure:70, auth_state:85, capability:30→70 on DLMS reply,
  impact_class:65, cve_exposure:0}. 23 protocol plugins now
  register in the default build (22 → 23); 7 wire tests + 9
  plugin tests; `make ci` green, 0 lint, 0 sec.

- 2026-04-28 — v1.21 (chunk 2) — **M-Bus over TCP fingerprint
  plugin on TCP/10001.** Second chunk of v1.21. Sends a 5-byte
  REQ_UD2 short frame to broadcast primary address 0xFE per
  EN 13757-3 §5.2 and folds the parsed manufacturer code +
  medium byte from the RSP_UD long-frame response into the
  finding hash. ACK-only responses (single byte 0xE5) also count
  as positive identification. `internal/protocols/mbustcp/wire/`
  carries the from-scratch frame parser including BCD ID
  extraction + M-Bus 16-bit-packed-3-letter manufacturer-code
  decoder (canonical ABB / KAM / ELS / SEN families).
  ProxyHandler is wire-layer write-ban: reads the request and
  replies with a single-byte ACK (0xE5) — matches the protocol's
  own link-layer ACK idiom, the closest "request denied" surface
  M-Bus has. Score factors{protocol_risk:70, exposure:70,
  auth_state:90, capability:30→70 on M-Bus reply, impact_class:60,
  cve_exposure:0}. 22 protocol plugins now register in the
  default build (21 → 22); 11 wire tests + 9 plugin tests;
  `make ci` green, 0 lint, 0 sec.

- 2026-04-28 — v1.21 (chunk 1) — **KNXnet/IP UDP fingerprint
  plugin on UDP/3671.** First chunk of the v1.21 cycle (continuing
  the legacy ICS fingerprint roll-out from v1.20).
  `internal/protocols/knxip/wire/` carries the from-scratch
  DESCRIPTION_REQUEST builder + DESCRIPTION_RESPONSE parser per
  KNX Standard 03.08.02 §2.2; validates header bytes 0x06 0x10,
  service type 0x0205, total-length consistency, device-info DIB
  type 0x01 at offset 7. Trims NUL/space padding off the 30-byte
  ASCII friendly name with a single-pass cutset. Plugin uses an
  anonymous control HPAI (0.0.0.0:0) which is the canonical
  shape for unsolicited probes. ProxyHandler is fail-closed
  (UDP). Score factors{protocol_risk:75, exposure:75, auth_state:90,
  capability:30→75 on KNX reply, impact_class:70, cve_exposure:0}.
  21 protocol plugins now register in the default build (20 → 21);
  9 wire tests + 7 plugin tests; `make ci` green, 0 lint, 0 sec.

- 2026-04-28 — v1.20 (chunk 3) — **GE-SRTP TCP fingerprint plugin
  on TCP/18245.** Third of three legacy-ICS fingerprint plugins
  scheduled for v1.20. `internal/protocols/gesrtp/wire/` carries
  the 56-byte CONNECTION INIT mailbox builder + ClassifyResponse
  function reverse-engineered from Rapid7's nmap NSE script
  `gesrtp-info` and Conpot's GE simulator fixtures. Probe sends
  byte 0 = 0x02, reads exactly 56 bytes, classifies by the
  response type byte (0x03 = response). Public protocol
  documentation is sparse so deeper service-code probing (CPU
  model identification via service 0x21) is deferred — the plugin
  captures "56-byte SRTP mailbox came back" as the fingerprint
  signal and surfaces shape errors via classifyParseError ("short
  SRTP frame (N bytes)" / "SRTP response type byte not 0x03").
  ProxyHandler is wire-layer write-ban: reads the client mailbox,
  replies with a 56-byte mailbox carrying byte 0 = 0x03 + byte 42
  = 0x01 (non-zero status indicator); does NOT forward to upstream.
  Score factors{protocol_risk:80, exposure:75, auth_state:95,
  capability:30→70 on SRTP reply (slightly lower than finsudp/slmp
  because the connection-init classifier doesn't decode the
  response payload — operators get less actionable detail), impact_
  class:75, cve_exposure:0}. 20 protocol plugins now register in
  the default build (19 → 20); 6 wire tests + 7 plugin tests;
  `make ci` green, 0 lint, 0 sec.

- 2026-04-28 — v1.20 (chunk 2) — **MELSEC SLMP TCP fingerprint
  plugin on TCP/5007.** Second of three legacy-ICS fingerprint
  plugins scheduled for v1.20. `internal/protocols/slmp/wire/` carries
  the from-scratch READ CPU MODEL NAME (command 0x0101, subcommand
  0x0000) request builder + 3E-frame response parser per Mitsubishi
  Electric SLMP Reference Manual SH(NA)-080956ENG; validates
  subheader 0xD000, declared-length consistency, end-code zero;
  caps the declared-length field at 8192 to defuse oversized-length
  attacks; trims NUL/space padding off 16-byte ASCII Model. Plugin
  layer dials TCP, reads the 9-byte header first to learn the body
  length, then reads the body (with growth fallback if the initial
  buffer was too small). ProxyHandler is wire-layer write-ban: reads
  the request header + body, replies with a 13-byte error frame
  carrying SLMP end code 0xC059 ("command unsupported" per §6.6
  end-code table); does NOT forward to upstream. Score
  factors{protocol_risk:80, exposure:75, auth_state:95, capability:
  30→75 on SLMP reply, impact_class:75, cve_exposure:0}. 19 protocol
  plugins now register in the default build (18 → 19); 9 wire tests
  + 11 plugin tests; `make ci` green, 0 lint, 0 sec.

- 2026-04-28 — v1.20 (chunk 1) — **Omron FINS UDP fingerprint plugin
  on UDP/9600.** First of three legacy-ICS fingerprint plugins
  scheduled for v1.20. `internal/protocols/finsudp/wire/` carries
  the from-scratch CONTROLLER DATA READ (MRC=0x05, SRC=0x01) request
  builder + response parser per OMRON CPU manual W421 §5.1/§5.4;
  validates ICF response bit, SID echo, MRC/SRC match, end-code
  zero; trims NUL/space padding off 20-byte ASCII Model. Plugin
  layer dials UDP, fresh non-zero SID via `crypto/rand`, classifies
  parse errors into operator-facing notes (short FINS frame / SID
  echo mismatch / FINS end-code non-zero / not-a-response).
  ProxyHandler is fail-closed (TCP framework can't relay UDP) — a
  dedicated UDP relay arrives with the future offensive write
  plugin. Score factors{protocol_risk:80, exposure:80, auth_state:95,
  capability:30→75 on FINS reply, impact_class:75, cve_exposure:0}.
  18 protocol plugins now register in the default build; 17 wire
  tests + 11 plugin tests; `make ci` green, 0 lint, 0 sec.

- 2026-04-19 — F0 — Scaffolding initialised. Context system populated with
  36 PITFs, 26 ADRs, templates, and per-topic canonical docs. Repository
  tree created per section 6 of the project brief.
- 2026-04-19 — F0 — **Closed.** `make ci` green end-to-end on operator's
  machine: golangci-lint v2 (0 issues), build × 3 variants, race + cover,
  fuzz smoke (2 targets: SafeBytes, SafeCommand flag validator), sec
  (gosec 0, govulncheck 0, trivy 0, go-licenses 0, gitleaks 0),
  context-check. .golangci.yml ported to v2 config format;
  .gitleaks.toml tightened so empty .env.example placeholders no longer
  trigger (regression guard for PITF-010).
- 2026-04-19 — F1 (chunk 1) — cobra rewires cmd/elsereno with a real
  verb tree (version/doctor/legal/plugins/config/scoring) and typed
  stubs for the rest. Koanf loader with struct-tag walker rejects
  unknown YAML keys via ErrUnknownConfigField. Zerolog logger +
  Redact(key, value) with entropy heuristic (>4.5 bits/byte) and a
  UUID v1–v5 exemption (PITF-004). pgx pool enforces
  database.tls_required per ADR-021. Goose migration runner wired to
  embedded SQL (stdlib bridge pending chunk 2). Inputs: list, stdin,
  nmapxml. Outputs: NDJSON (ndjson:v1) and CSV (csv:v1). Scoring engine
  v1 with embedded defaults/weights.yaml (ADR-006). Doctor checks go
  runtime, platform, CAP_NET_RAW / root, nmap presence, IPv6, and disk.
  `make ci` green again.
- 2026-04-19 — F1 (chunk 2) — vault (AES-GCM + Argon2id + HKDF +
  memguard) with unlock-once, Lock zeroisation, Init refuses silent
  re-init; goose migrations runnable via pgx stdlib bridge
  (OpenDBFromPool); Prometheus metrics (findings_total,
  scan_duration_seconds, persistence_lag_seconds, audit_entries_total,
  outbox_inflight) + label sanitiser (protocol / severity to a fixed
  set; ASN numeric; country ISO 3166-1 alpha-2; else "unknown");
  scanner core with resolve (A+AAAA+IDN), Dedupe, concurrent probes
  with per-host + global semaphores, token-bucket rate limiting,
  exponential backoff+jitter retries; triage grouping
  (quick_win/strategic/routine); HTML output (html:v1); Shodan REST
  client. `make ci` green. F1 snapshot written.
- 2026-04-19 — F1 (chunk 3) — **F1 closed.** CLI wiring for
  vault/creds/db/audit/serve/scan/explain/why/triage/lint/fmt. File-
  backed vault at ~/.elsereno/vault.v1.bin. Real JCS audit
  canonicalisation. Scanner CircuitBreaker + TemporalDedupe (5 min).
  Censys v2 client. Progress bars. Outbox worker with dead-letter.
  Retention with keep-if-referenced. Web server scaffold with full
  timeouts + CSRF HKDF. banner plugin (first real Protocol).
  Integration test scaffold.
- 2026-04-19 — F2 — **F2 closed.** XOT (RFC 1613) and AT-modem
  plugins land: from-scratch wire parsers (header + X.25 PTI
  classifier for XOT; line-oriented state machine for AT with
  CR/LF tolerance, 64 KiB ceiling, +CME/+CMS error codes, CONNECT
  recognition). Vendor detection for Hayes / GSM (Siemens, Nokia,
  Sierra, MultiTech, Cinterion, Telit, u-blox, Quectel, Huawei) and
  EN 81-28 lifts (KONE, Otis, Schindler). Probe plugins + simulators
  (`simulators/xot/`, `simulators/atmodem/`). Proxy handlers: XOT
  pass-through; AT proxy drops the full write-ban set (ATD*, ATA,
  AT+CMGS, AT+CMGW, AT+CMSS, AT+CMGD, AT+CFUN, AT+CPWROFF, +++).
  ADR-027, ADR-028. `make ci` green end-to-end (seven fuzz targets,
  ~4 min wall-clock). F2 snapshot written. Repo is at the brief's
  F2 milestone — ready for `git push` to a private GitHub remote.
- 2026-04-19 — F3 — **F3 closed.** Proxy framework under
  `internal/proxy` (TCP listener, Accept loop, IdleTimeout-driven
  deadlines, graceful ctx-cancel shutdown, `Hook` interface with
  optional rewrite semantics, LoggingHook over SafeBytes). Modbus/TCP
  plugin: from-scratch wire parser (MBAP + PDU + FC classifier +
  exception helper + FC 43/14 Device ID decoder + 3 fuzz targets),
  Probe (FC 1 + opportunistic FC 43/14 vendor strings), and proxy
  that short-circuits every CategoryWrite / non-14 MEI / unknown FC
  with IllegalFunction — upstream never sees a write. Modbus
  simulator (`simulators/modbus/`) on Go, plus a pymodbus runtime
  pointer. Chaos helpers under `test/chaos/` (RandomDropReader,
  LatencyReader, FlipBitsWriter, EarlyCloser — build tag `chaos`).
  ADR-029, ADR-030. Integration test
  `test/integration/modbus_integration_test.go` end-to-end through
  the framework. `make ci` green (ten fuzz targets, ~9 min wall-clock
  with trivy DB refresh).
- 2026-04-19 — F4 — **F4 closed.** Eight new ICS plugins land in one
  pass, all with from-scratch wire parsers + probe + fuzz target +
  ADR + protocol doc:
  s7 (TPKT/COTP port 102), enip (EtherNet/IP CIP ListIdentity port
  44818), bacnet (BVLC Who-Is UDP/47808), dnp3 (IEEE 1815 link
  frame port 20000), iec104 (APCI TESTFR port 2404), hartip
  (session initiate port 5094), fox (Niagara Fox banner 1911/4911),
  atg (Veeder-Root I20100 port 10001). banner plugin grows a
  DetectVendor() helper with Moxa/Lantronix/Digi/NetBurner/KONE/
  Otis/Schindler/OpenSSH rules. 12 plugins total registered.
  Dashboard MVP at `/` (inline HTMX-ready HTML listing plugins) +
  JSON API at `/api/v1/{plugins,scoring,health}` with
  `{schema: "api:v1", data: …}` envelope. OpenAPI 3.1 spec at
  `docs/openapi.yaml`. Conpot honeypot added to
  `simulators/docker-compose.test.yml` with mapped ports for all 8
  new plugins. ADRs 031..038. A fuzz-found panic in enip ListIdentity
  parser (truncated body) was fixed with stricter bounds checks;
  corpus entry retained as regression guard. `make ci` green (18
  fuzz targets). REPL bindings + Bearer-auth on /api/v1 + full
  dashboard UI land in F4 chunk 2 / F5.
- 2026-04-19 — F5 — **Closed.** Offensive build behind `-tags offensive`.
  ADR-039 triple-confirm wrapper (build tag + --accept-writes +
  --confirm-target + HMAC-SHA256 token via HKDF
  `info="elsereno/offensive/confirm/v1"`). ADR-040 per-plugin proxy
  write-gating for the 7 F4 pass-through plugins plus atg/fox/bacnet.
  ADR-041 dial guard with unbypassable ≤3-digit hard block. ADR-042
  seccomp-bpf scaffold (Linux PR_SET_NO_NEW_PRIVS; BPF filters land
  with F6 subprocess integrations). `offensive/write/{modbus,s7,enip,
  bacnet}` writers with deterministic SHA-256 payload hashes.
  `offensive/dial/Validate` three-gate validator. `offensive/harvest`
  probers for Telnet / FTP / HTTP-Basic / SNMPv2c. `offensive/exploits`
  registry + 2 public-stable DoS modules (CVE-2015-5374 Siemens
  SIPROTEC, CVE-2019-10953 CIP ListIdentity). `internal/canary`
  webhook sender with optional HMAC signature.
  `internal/exec.CommandSpec.AllowAnyPath` bypass with mandatory
  BypassAuditor. Default build remains read-only end-to-end; no
  offensive code path is reachable without the build tag.
  `make ci` green on both build variants. CLI wiring for
  `elsereno write|exploit|harvest|dial` lands with the DB-backed
  audit writer in F6.
- 2026-04-20 — F6 — **Closed.** Reporting + release. Five new output
  sinks: CEF 0.1 + RFC 5424 syslog + JIRA Cloud REST v3 + GitHub
  Issues REST + generic HMAC-signed webhook. HTML report polish
  (dark-mode, per-protocol sections with count/max/avg, top-5
  factor histogram). OpenAPI 3.1 autogen: code-sourced
  `internal/web/openapi.Spec()` + live `/api/v1/openapi.yaml` +
  `elsereno api openapi` CLI. Offensive CLI verbs (`write|exploit|
  harvest|dial`) land behind `-tags offensive`; all four are
  operator-usable today (delivery wiring carries over to F7 with
  the DB-backed audit writer). `--vault-passphrase-file <0600
  path>` unblocks non-interactive startup; mode + symlink + empty-
  file validation. 13 operator docs (`docs/protocols/*.md` + README
  + RELEASING.md). Dashboard polish with dark-mode palette, plugin
  grouping default vs offensive, scoring sidebar, severity chips.
  `.goreleaser.yml` migrated to v2 archives.ids; dry-run validated
  8 binaries × SBOM × SHA-256 checksums. F7 open carry-overs:
  dockers_v2 migration, offensive network delivery, seccomp-bpf
  filter sequences, SSE + findings/triage/runs DB panels.
- 2026-04-20 — F7 — **Closed.** Hardening + 1.0. Dockers_v2 migration +
  nightly per-target fuzz matrix. Regression benchmarks with benchstat
  CI comment. OpenTelemetry tracing scaffold + scanner spans. 6 STRIDE
  threat-model docs under `.context/threat-model/` (vault-audit, web,
  scanner-proxy, exec-scope, offensive, telemetry-canary). Supply-
  chain automation: OpenSSF Scorecard nightly, SLSA L3 provenance on
  tag, dependency-review with licence deny-list, osv-scanner,
  licenses-audit artefact. `internal/backup`: AES-256-GCM + two-stage
  HKDF + tar/gzip payload + 10 unit tests. `elsereno backup
  create|restore|inspect` CLI verbs honouring
  --vault-passphrase-file. Pentest dashboard panel at /admin/security
  showing 11 in-process controls + threat-model links + external
  sec-suite references. `scripts/release-gate.sh` + `make release-
  gate` + RELEASING.md 1.0 section. `SUPPLY-CHAIN.md` documents SLSA
  mapping + dep policy + SBOM diff recipe + secrets rotation table.
  Feature-complete for v1.0.0; tag is an operator task.
- 2026-04-20 — **Release v1.0.0** pushed to private repo
  RobinR00T/elSereno. 12 release assets: 5 archives (darwin/linux
  × amd64/arm64 + sqlite linux-amd64) + 6 CycloneDX SBOMs +
  cosign-signed checksums. Tag signed with GPG
  ACE3B86BACACE7D6. Known issues: `.intoto.jsonl` SLSA provenance
  missing (v2.0.0 generator finaliser bug; v1.0.1 fixes via
  v2.1.0), cosign `.sig` without `.bundle` (v1.0.1 adds bundle),
  GHCR image disabled (v1.1 carry-over).
- 2026-04-21 — **Release v1.0.1 polish** queued on main: cosign
  `--bundle`, SLSA generator bumped v2.0.0 → v2.1.0, pandoc
  pinned to upstream 3.9.0.2 .deb for determinism, README
  badges + signed-install recipe. Source code unchanged; config
  + docs only.
- 2026-04-21 — **v1.0.1** released. checksums.txt.bundle
  shipped; end-to-end cosign-verify-blob confirmed. SLSA
  `final` step still fails upstream (wrapped non-blocking in
  release.yml); `.intoto.jsonl` not on release yet.
- 2026-04-21 — **v1.1 chunks 1-3** landed on main: per-plugin
  offensive WriteGatedHandler (modbus/s7/enip full + 6 session
  primitives), file-backed audit writer + confirm adapter,
  network delivery wiring for `write modbus send` / `exploit
  run` / `audit verify-file`. 4 chunks pending: SSE + DB
  panels, GHCR image, BPF filters, OPC UA, wardialing batch.
- 2026-04-21 — **v1.1 chunk 4 (SSE half)** landed on main: new
  `internal/web/stream` package with channel-per-subscriber
  Broadcaster (slow-subscriber-dropped fan-out), `/api/v1/stream`
  SSE handler with retry + keepalive, dashboard live-feed panel
  (EventSource, CSP-nonce script), audit.Observer hook +
  `TailAudit` cross-process file tailer so offensive verbs in
  separate processes light up the dashboard. OpenAPI spec +
  `docs/openapi.yaml` snapshot include `/api/v1/stream`. DB
  tables + findings/triage/runs panels carry over into v1.2
  alongside the DB-backed audit Writer.
- 2026-04-21 — **v1.1 chunk 5 (GHCR docker image)** landed on
  main: `.goreleaser.yml` `dockers_v2` block with `sbom: true`
  (CycloneDX attestation) + `--attest=type=provenance,mode=max`,
  multi-arch (linux/amd64 + linux/arm64) under
  `ghcr.io/robinr00t/elsereno:<tag>` + `:latest`, cosign keyless
  `docker_signs` on the manifest. `.github/workflows/release.yml`
  adds `docker/setup-qemu-action@v3` + `docker/setup-buildx-action@v3`
  so the multi-arch + attestation pipeline works end-to-end.
  `Dockerfile` + `Dockerfile.sqlite` pin Go 1.25.4 (matching
  go.mod) on Alpine 3.22 / Debian bookworm. README + RELEASING
  documented with pull + cosign-verify recipes.
- 2026-04-21 — **v1.1 chunk 6 (seccomp-bpf sandbox)** landed on
  main: `offensive/sandbox/bpf_linux.go` compiles per-profile
  denylist BPF programs (prologue: LD arch / JEQ / LD nr;
  body: one JEQ per blocked syscall; tail: RET ALLOW / RET
  ERRNO|EPERM). `syscalls_linux.go` ships syscall-number tables
  for x86_64 + aarch64 (generic ABI, zero-entries dropped so
  unsupported syscalls don't accidentally match `read` at nr=0).
  `sandbox.Load` installs via `seccomp(SECCOMP_SET_MODE_FILTER,
  TSYNC)` so the filter covers every goroutine-backing thread.
  `offensiveRuntime.ApplySandbox` records an `offensive_sandbox`
  audit entry (new `audit.EventOffSandbox` + migration 00002)
  capturing profile + availability + kind. Wired into `write
  modbus send`, `exploit run`, and `harvest *` so they install
  the profile before any network I/O. Integration tests under
  the `sandbox_integration` build tag fork a child + verify
  ptrace (exploit) and socket (dial) return EPERM on native
  Linux. Legacy top-level `migrations/` dir removed — the
  `internal/db/migrations/` embed is the single source of truth.
- 2026-04-21 — **v1.1 chunk 7 (OPC UA plugin)** landed on main:
  `internal/protocols/opcua/wire/` parses + encodes UA-TCP Part 6
  Hello/Acknowledge/Error frames; `internal/protocols/opcua/`
  registers the plugin on port 4840. Probe sends a minimal HEL
  and classifies the response (ACK, ERR, or non-UA bytes) into
  a scored Finding; default ProxyHandler refuses with a UA-native
  ERR frame (Bad_ResourceLimitsExceeded + "denied") so real
  clients get a parseable rejection. `simulators/opcua/` ships a
  minimal Go UA-TCP responder for CI. Write-gating deferred to
  v1.2 once the SecureChannel + Session + Write surface is
  modelled (too large for v1.1). E2E verified against the
  simulator: probe → ua-ack → severity=high score=66.
- 2026-04-22 — **v1.2 extra: `audit.SyncFromFile` helper**
  bootstraps a fresh DB (DBMirror / FileMirror) from an
  existing JSONL audit chain — typical use case is an operator
  who ran v1.0→v1.1 with just the FileWriter, spins up a
  Postgres in v1.2, and wants the history migrated without
  losing chain continuity. The helper walks the file,
  re-validates every prev_hash + entry_hash (detects silent
  tamper), skips IDs already in the target (via an operator-
  supplied `ExistingIDFunc` — `DBExistingID(conn)` is the
  pgx-backed default), then calls MirrorWriter.Mirror
  verbatim. Returns the count of imported entries + a typed
  error on any chain discrepancy. 3 unit tests cover the
  happy path, idempotent re-import, and tamper detection.
- 2026-04-26 — **v1.15 chunk 5 landed.** SIGHUP reload-style
  graceful exit on `proxy listen`. The constraint that
  prompted the design choice: each per-session
  confirm-token is computed from the operator-supplied
  allowlist's hash, so any in-process allow-file reload
  invalidates the existing token (operator must re-mint
  before the new allowlist activates). Rather than
  building a token-generation cookie scheme + re-authorise-
  in-place plumbing, chunk 5 takes the supervisor-restart
  path: SIGHUP triggers a clean exit with code 75 / EX_TEMPFAIL
  (distinguishable from a real crash via systemd's
  `RestartPreventExitStatus=`); SIGINT + SIGTERM keep the
  existing exit-0 behaviour. Operator workflow: edit
  /etc/elsereno/<plugin>-gate.yaml, run
  `elsereno-offensive write <plugin> dry-run` to mint the
  new confirm-token, write the new token to the supervisor's
  systemd-environment / runit env, `kill -HUP $(pidof …)`,
  supervisor restarts with updated config. The proxy
  long-help text gains a "SIGHUP reload via supervisor
  restart" section. 1 new test
  (TestErrReloadRequested_Sentinel) pins the typed-sentinel
  contract for the SIGHUP-exit error.
- 2026-04-26 — **v1.15 chunk 4 landed.** Audit chain cross-
  process merge. The race that prompted the chunk: two
  ElSereno processes (e.g. `serve` + `proxy listen` on the
  same operator workstation) both opening
  `~/.elsereno/audit.jsonl` and appending concurrently
  could produce two entries claiming the same prev_hash —
  the chain invariant breaks the moment the operator runs
  `audit verify-file`. Fix: an exclusive `unix.Flock(LOCK_EX)`
  guards the `Append`/`appendVerbatim` read-then-write
  critical section. Inside the lock, `resume()` re-reads
  the file from offset 0 to pick up entries another process
  may have appended since our last operation, advancing
  `nextID` + `prevHash` so our entry continues the merged
  chain. Linux + macOS only via `golang.org/x/sys/unix`
  (already a dep); Windows stub returns nil from both
  lock/unlock methods (Windows support is tracked in the
  v1.15+ backlog as a cross-cutting cycle including
  AppContainer / Job Objects in addition to flock). 2 new
  tests: TestFlock_TwoWritersInterleaveCleanly (50 entries
  across two FileWriters, asserts strictly increasing IDs +
  chain invariant + both actors represented),
  TestFlock_AppendVerbatimAlsoLocked (5 sequential appends
  through the public path proves unlock fires correctly —
  we'd deadlock on the second call without it).
- 2026-04-26 — **v1.15 chunk 3 landed.** STIX 2.1 export sink.
  Findings can now flow into MISP / OpenCTI / ThreatBus / any
  STIX 2.1 consumer via `elsereno scan --output-format stix`.
  Each finding maps to three STIX objects bundled together:
  ipv4-addr or ipv6-addr SCO (target's address), network-
  traffic SCO (target's port + protocols list), observed-data
  SDO (timestamps + severity/protocol labels referencing the
  network-traffic SCO). Wire format: JSON per STIX 2.1 §10
  with 2-space indent. Deterministic UUIDv5 IDs keyed on the
  finding ID + ElSereno-private namespace UUID
  (`0a8b1d4e-3f6c-5a7d-9e2f-7c1b3d4e5f60`) — re-running a
  scan over the same fixture produces byte-identical inner
  objects (the bundle ID itself is timestamp-bound, so the
  outer envelope differs by run, but the inner SCOs/SDOs are
  stable for diff-based regression testing). Transport-layer
  protocol selection: BACnet + IAX2 → "udp", everything else
  → "tcp" (the application-layer protocol is appended in the
  protocols array). Empty addr (caller couldn't resolve)
  emits 2 objects instead of 3 — net-traffic SCO + observed-
  data SDO without dst_ref. 9 new tests:
  TestWriteFinding_BundleEmitsThreeObjects (3 objects per
  finding), TestWriteFinding_IPv4AddrSCO + TestWriteFinding_IPv6AddrSCO
  (address-family selection), TestWriteFinding_NetworkTrafficSCO
  (port + protocols), TestWriteFinding_BACnetUsesUDPTransport
  (UDP-only protocol), TestWriteFinding_ObservedDataSDO
  (timestamps + labels), TestWriteFinding_DeterministicIDs
  (same input → same inner-object IDs across runs),
  TestWriteFinding_EmptyAddrSkipsAddrSCO (graceful fallback),
  TestWriteFinding_RequiresID (empty Finding.ID errors),
  TestWriteFinding_BundleSpecVersion (2.1 conformance pin).
- 2026-04-26 — **v1.15 chunk 2 landed.** `elsereno discover
  --auto <CIDR>` TCP-connect sweep. Operator-UX win:
  point-and-shoot scanning. The sweep iterates the CIDR,
  probes the well-known port of every registered plugin
  (built from `core.RegisteredPlugins()`), and emits
  responsive `(host, port)` pairs as NDJSON (default) or
  `host:port` list. Output goes to stdout for pipe-friendly
  composition: `elsereno discover --auto 192.168.1.0/24
  --format list | elsereno scan --input list:-`.
  Implementation: parallel TCP-connect (default 64
  concurrent) with per-attempt dial-timeout (default 1 s).
  Bounded by `--max-hosts` (default 256, /24-sized) so a
  bare `--auto 10.0.0.0/8` doesn't accidentally fire 16 M
  connects. CIDR expansion goes through `netip.ParsePrefix`
  + `Prefix.Masked()` + iterative `Addr.Next()` — IPv4 and
  IPv6 prefixes both work (chunk-4-of-v1.14 contract). Port-
  registry collisions (e.g. future IEC 61850 MMS sharing 102
  with S7) emit ALL claiming plugins in `protocol_hints`.
  9 new tests: CIDR expansion (v4 /30, v6 /126, max-hosts
  cap, malformed input), port-registry helpers (shared port
  lists all, no-match returns nil), sweep e2e (responding
  port detected, dead port ignored), output format
  (ndjson, list, bad format errors).
- 2026-04-26 — **v1.15 chunk 1 landed.** CWMP TransferComplete
  observer. Closes the loose-end from v1.12 chunk 10's
  firmware-pinning work: the operator pins
  `{URL, SHA256}` on Download authorisation, but the gate
  never observed the CPE's eventual report on whether the
  download completed (success or failure). v1.15 chunk 1
  adds a passive observer hook on the CWMP gate that fires
  when a CPE → ACS TransferComplete envelope traverses the
  proxy. The hook is opt-in via the
  `WriteGatedHandler.OnTransferComplete` callback field;
  when set, the gate parses the SOAP body to extract
  CommandKey + FaultStruct (FaultCode + FaultString) +
  StartTime + CompleteTime, then forwards the request
  unchanged. Default CLI observer (in
  `cmd_proxy_offensive.go`) emits a stderr structured log
  line per envelope:
  `TIMESTAMP level=info msg=cwmp_transfer_complete target=…
  status=ok|fault command_key=… fault_code=… fault_string=…
  start=… complete=…`. New `TransferCompleteFields` struct
  with `IsSuccess()` helper (FaultCode == "0"). Wire parser
  uses streaming xml.Decoder pattern shared with
  extractDownloadURL + extractParameterNames — no full SOAP
  tree materialisation. The library
  `internetdb.Client`-style separation is preserved: the
  CWMP gate doesn't make HTTP calls or compute SHA-256 itself
  (TR-069 doesn't carry a hash in TransferComplete);
  operator-side correlation between Download authorisation
  and TransferComplete observation happens via the audit
  chain (CommandKey field). 6 new tests:
  TestObserveTransferComplete_SuccessPath (FaultCode=0,
  observer fires, request forwards),
  TestObserveTransferComplete_FaultPath (FaultCode=9010,
  IsSuccess=false), TestObserveTransferComplete_NotInvokedForOtherRPCs
  (Inform/Kicked/Fault don't trigger observer),
  TestObserveTransferComplete_NilObserverNoOps (regression
  guard for nil-check), TestObserveTransferComplete_MissingCommandKey
  (older CPEs send empty/missing CommandKey — gate
  tolerates), TestTransferCompleteFields_IsSuccess (pinned
  semantics: exactly "0" → success).
- 2026-04-26 — **v1.14 chunk 4 landed.** IPv6 coverage tests
  for scope + dedupe paths. Audit-only chunk: confirms the
  existing `netip.Addr` + `Unmap()` infrastructure correctly
  handles IPv6 across the scope-gate and target-deduplication
  layers. No code change needed — the infrastructure was
  already correct; chunk 4 pins the contract via tests so a
  future refactor can't silently break the v6 path.
  - `internal/scope/scope_ipv6_test.go` (5 tests):
    `TestCheck_IPv6_InRange` (target inside 2001:db8::/32),
    `TestCheck_IPv6_LoopbackHostPrefix` (::1/128 host-prefix
    match), `TestCheck_IPv6_OutOfRange` (link-local
    fe80::/10 out-of-scope), `TestCheck_IPv4MappedIPv6_MatchesV4Range`
    (`::ffff:192.168.1.5` matches v4 CIDR via `.Unmap()` — the
    canonical safety invariant: scope cannot be bypassed by
    using the v4-mapped form), `TestCheck_IPv4Target_DoesNotMatchIPv6Range`
    (no cross-family leakage).
  - `internal/scanner/dedupe_ipv6_test.go` (4 tests):
    `TestDedupe_IPv4MappedIPv6CollapsesWithBareV4`
    (`::ffff:1.2.3.4` + `1.2.3.4` collapse to one target),
    `TestDedupe_IPv6FormsCollapse` (longform/shortform both
    canonicalise via `netip.Addr` storage),
    `TestDedupe_IPv6vsIPv4DistinctTargets` (`::1` and
    `127.0.0.1` stay separate — different address families),
    `TestDedupe_DifferentPortsKept` (same IPv6 + different
    ports stay separate).
- 2026-04-26 — **v1.14 chunk 3 landed.** `scan --input
  internetdb:` IPv6 fixes. Two real bugs: (a) the dispatcher
  in `cmd_scan.go` had no case for `internetdb:` — the CLI
  accepted the prefix but `readTargets` errored as "unknown
  input kind" (regression introduced in v1.13 chunk 1 —
  `readInternetDBTargets` was wired through
  `readTargetsFromProvider` but the dispatcher case was
  forgotten); (b) even when dispatched, `netip.ParseAddr`
  rejects bracketed IPv6 literals like `[2001:db8::1]` so
  `--input internetdb:[2001:db8::1]` always failed. Both
  fixed. New helper `stripIPv6Brackets` at the CLI boundary
  strips leading-`[` + trailing-`]` (mirrors the host:port
  bracket convention operators already use for `--target` /
  `--listen`). Applied to single-IP form
  (`internetdb:<ip>`), file-bulk
  (`internetdb:file:<path>` — bracketed lines tolerated), and
  stdin-bulk (`internetdb:-`). The `cmd_scan.go` dispatcher's
  "unknown input kind" error now mentions `internetdb:<ip>`
  in the list of valid prefixes. 14 new tests:
  TestStripIPv6Brackets (10 input shapes incl. unmatched-
  bracket pass-through), TestReadInternetDBTargets_BracketedIPv6
  (httptest-driven IPv6 round-trip — verifies the upstream
  receives the canonical bare-literal path
  `/2001:db8::1`), TestReadTargets_InternetDBDispatchWired
  (regression guard: dispatcher must NOT return "unknown
  input kind" for `internetdb:` prefix).
- 2026-04-26 — **v1.14 chunk 2 landed.** Target
  canonicalisation across proxy listen + every dry-run
  command. The operator UX hazard: write
  `[0:0:0:0:0:0:0:1]:7547` in dry-run, write `[::1]:7547`
  in `proxy listen` → byte-for-byte compare fails, hash
  diverges, confirm-token mismatches. v1.14 chunk 2 closes
  this gap by canonicalising target / listen / confirm-target
  strings via the chunk-1 `netutil.CanonicalHostPort`. RFC
  5952-canonical IPv6 forms (longform → short, lowercase
  hex) make every equivalent input collapse to the same
  string — hash + token match downstream. New helper
  `canonicaliseTarget` in `cmd_write_gates_offensive.go`.
  Wire-up: `runProxyListen` (target / listen / confirmTarget
  after loadAllowFile + validate); 6 dry-run RunE handlers
  (sip / iax2 / pbxhttp / modbus / opcua / cwmp);
  `runBACnetDryRun`. Backwards-compat: IPv4 forms unchanged,
  already-canonical IPv6 forms unchanged — only operators
  using IPv6 longform / uppercase need to re-mint tokens.
  9 new tests: `TestCanonicaliseTarget_IPv6FormsConverge`
  (longform/shortform/uppercase variants → same canonical
  string), `TestCanonicaliseTarget_HostnameUnchanged`
  (localhost / hostnames pass through), per-plugin hash-
  equivalence regressions for BACnet / OPC UA / SIP / IAX2 /
  pbxhttp / CWMP.
- 2026-04-26 — **v1.14 chunk 1 landed.** IPv6 foundation —
  the v1.14 cycle opens with the operator-requested
  cross-cutting IPv6 work (2026-04-25). New
  `internal/netutil` package with `IsLoopbackHostPort` +
  `CanonicalHostPort` + `ParseAddrPort` helpers. Replaces the
  substring-based loopback check in `cmd_serve.go` (which
  missed IPv6 longform `[0:0:0:0:0:0:0:1]:port`, zone-scoped
  `[::1%lo0]:port`, and IPv4 anywhere-in-127/8 like
  `127.0.0.5:8787`). The new helper delegates to
  `netip.ParseAddrPort` + `Addr.IsLoopback()`, which handle
  every spec-conformant variant per RFC 1122 (IPv4) + RFC 5952
  (IPv6). `CanonicalHostPort` normalises IPv6 longform → short,
  lowercase hex, etc. — useful when the rest of the cycle adds
  IP-allowlist deduplication. 18 unit tests cover IPv4
  loopback (127.0.0.1, 127.0.0.5, 127.255.255.255), IPv6
  shortform (`[::1]:port`), longform
  (`[0:0:0:0:0:0:0:1]:port`), zone-scoped (`[::1%lo0]:port`),
  hostname (`localhost:port`), unspecified (`[::]:port` —
  NOT loopback), and various non-loopback / malformed
  rejection cases.
- 2026-04-26 — **v1.13.0 PUBLISHED on GitHub Releases**
  (https://github.com/RobinR00T/elSereno/releases/tag/v1.13.0).
  9 assets (4 archives + 4 CycloneDX SBOMs + checksums.txt).
  Tag GPG-signed with `ACE3B86BACACE7D6`. Free-tier flow
  (goreleaser local + `gh release create`). Cycle-close
  commit `eb6f383`; v1.13.0-released memory commit `8f4b220`.
- 2026-04-26 — **v1.13 chunk 13 landed.** BACnet
  Add/RemoveListElement (svc 8/9) per-(object, property)
  allowlist. **CLOSES every BACnet mutating service** — all
  9 (svc 7/8/9/10/11/15/16/17/20/27) now have wire-level
  per-target-or-state allowlists. AddListElement and
  RemoveListElement share the SAME request shape per ASHRAE
  135 §15.1 + §15.2 — `[0] objectIdentifier`, `[1]
  propertyIdentifier`, `[2] propertyArrayIndex` (optional),
  `[3] listOfElements`. The first two fields are exactly the
  WriteProperty prefix, so the gate reuses
  `wire.ParseWriteProperty` to extract the (type, instance,
  property) target — no separate parser needed. The same
  `AllowedListElements` list applies to BOTH services; an
  operator wanting different policy for add vs remove must
  omit one from `--service-choice`. **Separate from
  AllowedObjects** (svc 15/16 WriteProperty) — property
  writes don't auto-grant list-mutations. Common targets:
  NotificationClass#N.recipient_list (102) — adding an
  unauthorised pager; Schedule#N.exception_schedule (38) —
  appending a date-window override; access-zone occupant
  lists. New CLI flag `--list-element type=N;instance=M;
  property=P` (repeatable); YAML field `list_elements:`
  (`{type, instance, property}`). New
  `AllowlistHashWithListElements` (separator 0xF8) extends
  the chunk-12 ladder; backwards-compat ladder degrades
  through chunks 12/11/10/9/8/7/v1.12-chunk-7/v1.4. Refactor:
  introduced `sortAllowedAtomicWriteFiles` helper; the
  `Allowlists` bundle gains a `ListElements` field;
  `parseAllowlists` adds the list-element dispatch step.
  `objectListGatesAllow` was split into
  `propertyTupleGatesAllow` (svc 8/9/15/16 — share the
  WriteProperty wire prefix) + `objectIdentityGatesAllow`
  (svc 7/10/11 — object-identity-only, no property
  dimension) for gocyclo. `buildAllowFileBACnet` now takes a
  `buildAllowFileBACnetInputs` struct (was 9 positional args)
  for readability. Extracted shared helpers
  `formatBACnetTupleList` + `bacnetTuple` +
  `canonAllowFileBACnetTuples` so chunk-7
  (canonBACnetObjects) and chunk-13 (canonBACnetListElements)
  share the parse/sort/format body — eliminates 4 dupl
  warnings. 9 new tests (4 hash ladder + 5 e2e covering both
  add and remove paths + the canonical "AllowedObjects entry
  doesn't auto-grant list-mutation" separation invariant).
- 2026-04-26 — **v1.13 chunk 12 landed.** BACnet
  AtomicWriteFile (svc 7) per-File-instance allowlist.
  Closes the file-overwrite surface: AtomicWriteFile is what
  operators use to replace firmware blobs, configuration
  files, and log files on the device — the same RPC that's
  the typical vehicle for malicious firmware swaps. The
  fileIdentifier in the request MUST be a File object
  (ObjectType=10 per ASHRAE 135 §15.8); the parser fails
  closed on any other ObjectType. The operator allowlists
  specific File instance numbers; the access specifier
  (stream vs record + byte offsets) is intentionally
  ignored at gate level — per-byte-range scoping has no
  operational use case in production. Typical pattern: when
  File#1 is firmware and File#5 is a rotating log, allow
  `--awf-file 5` to permit log writes + REFUSE firmware
  overwrites. New CLI flag `--awf-file N` (22-bit
  instance, repeatable); YAML field `awf_files:` (uint32
  list). Wire parser at `internal/protocols/bacnet/wire/
  atomicwritefile.go` — note that fileIdentifier in this
  service uses APPLICATION tag 12 (`0xC4`) NOT the
  context-tagged 0x0C form used elsewhere. New
  `AllowlistHashWithAWF` (separator 0xF9) extends the
  v1.13-chunk-11 ladder; backwards-compat ladder degrades
  through chunks 11/10/9/8/7/v1.12-chunk-7/v1.4. Refactor:
  introduced `sortAllowedLSOOps` helper; the `Allowlists`
  bundle gains an `AtomicWriteFiles` field; `parseAllowlists`
  adds the awf-file dispatch step. Also extracted
  `registerProxyListenFlags` + 5 per-plugin flag-registration
  helpers from `newProxyListenCmd` (which had grown over
  funlen with all the v1.13 dimensions); extracted
  `canonAllowFileBACnetObjects` + `canonAllowFileBACnetDeleteObjects`
  from `buildAllowFileBACnet`. 13 new tests (4 hash ladder +
  5 wire parser including ObjectType≠File fail-closed +
  large instance + 4 e2e covering the canonical "firmware
  refused, log allowed" safety invariant + non-File-type
  fail-closed at the gate level).
- 2026-04-26 — **v1.13 chunk 11 landed.** BACnet
  LifeSafetyOperation (svc 27) per-operation allowlist.
  Closes the most safety-critical BACnet service: silencing
  a fire-alarm panel during an active incident can be lethal.
  The 10-value ASHRAE 135 §21 BACnetLifeSafetyOperation enum
  has very different blast radii: 1/2/3 silence variants are
  HOSTILE (potentially lethal on production life-safety
  buses), 4/5/6 reset variants are operationally significant
  (clear alarm/fault state), 7/8/9 unsilence variants are
  the SAFE recovery direction. Typical operator pattern:
  allow 7/8/9 freely, allow 4/5/6 case-by-case after manual
  verification, REFUSE 1/2/3 outright. New CLI flag
  `--lso-op N` (0..9, repeatable); YAML field `lso_ops:`
  (uint8 list). Wire parser at `internal/protocols/bacnet/
  wire/lifesafetyoperation.go` walks the four-field request
  envelope (`[0] requestingProcessIdentifier`, `[1]
  requestingSource` CharacterString, `[2] request` ENUMERATED,
  `[3] objectIdentifier` OPTIONAL) using a generic
  `skipContextPrimitiveField` helper that handles inline
  length 0..4 + extended-length form (low-bits == 5 + length-
  byte-follows). The helper is reusable for future BACnet
  services with similar envelope structures. The optional
  [3] objectIdentifier is ignored at gate level (per-object
  scoping for LSO is a v1.14+ extension if asked); the
  process identifier and requesting source are operator-side
  metadata, not security-relevant. New
  `AllowlistHashWithLSOOps` (separator 0xFA) extends the
  v1.13-chunk-10 ladder; backwards-compat ladder degrades
  through chunks 10/9/8/7/v1.12-chunk-7/v1.4. Refactor:
  introduced `sortAllowedDCCStates` helper; the
  `Allowlists` bundle gains an `LSOOperations` field;
  `parseAllowlists` adds the lso-op dispatch step. 14 new
  tests (4 hash ladder + 7 wire parser including
  inline/length-2 processID + extended-length CharacterString
  + truncated/wrong-tag/out-of-range fail-closed + 5 e2e
  including the canonical "silence REFUSED when only
  unsilence is allowed" safety invariant + an "all silence
  variants refuse under recovery-only policy" sweep + a
  "reset+unsilence mix passes" composition test).
- 2026-04-25 — **v1.13 chunk 10 landed.** BACnet
  DeviceCommunicationControl (svc 17) per-state allowlist.
  The 3-value ASHRAE 135 §16.1 enableDisable enum has a clear
  asymmetry: 0 enable is the SAFE recovery direction (undoes
  an attacker-induced silence), 1 disable silences ALL BACnet
  communication (blocks monitoring + alarms during incidents),
  2 disableInitiation is a subtler attack (device responds to
  polls but won't initiate notifications). Typical operator
  pattern: allow only state 0 to permit recovery while
  refusing 1/2 to prevent silencing actions. New CLI flag
  `--dcc-state N` (0..2, repeatable); YAML field `dcc_states:`
  (uint8 list). Wire parser at `internal/protocols/bacnet/wire/
  devicecommcontrol.go` walks the optional [0] timeDuration
  (length 1..4 primitive context-tag-0 forms 0x09..0x0C) +
  required [1] enableDisable (`0x19 NN`); the optional [2]
  password CharacterString is ignored at gate level (between
  operator and device password policy). New
  `AllowlistHashWithDCCStates` (separator 0xFB) extends the
  v1.13 chunk-9 ladder; backwards-compat ladder degrades
  through chunks 9/8/7/v1.12-chunk-7/v1.4. Refactor: split
  `perObjectGatesAllow` into `objectListGatesAllow` (svc 10/11/
  15/16) + `stateListGatesAllow` (svc 17/20) for gocyclo;
  introduced `Allowlists` bundle struct (renamed from
  `BACnetAllowlists` per revive's package-stutter rule) so
  chunk-10+ hash + mutation factories take a single arg
  instead of growing per-cycle. CLI gained
  `parseAllowlists(in)` single-point-of-dispatch for every
  per-service dimension. 13 new tests (4 hash ladder + 6 wire
  parser including with/without timeDuration + length-1 vs
  length-2 forms + 5 e2e covering the canonical "disable
  REFUSED when only enable is allowed" + the subtler
  disableInitiation refusal).
- 2026-04-25 — **v1.13 chunk 9 landed.** BACnet
  ReinitializeDevice (svc 20) per-state allowlist. The 8-value
  ASHRAE 135 §16.4 reinitializedStateOfDevice enum has very
  different blast radii: 0 coldstart wipes runtime state, 1
  warmstart restarts the BACnet stack, 2..6 are backup/restore
  lifecycle states (destructive when interleaved), 7
  activate-changes is the post-config-update refresh and
  usually safe. Typical operator pattern: allow only state 7
  during a maintenance window. New CLI flag `--reinit-state N`
  (0..7, repeatable); YAML field `reinit_states:` (uint8 list).
  Wire parser at `internal/protocols/bacnet/wire/reinitialize
  device.go` reads the single primitive context-tag-0 length-1
  enum byte (`0x09 NN`) — the optional [1] password
  CharacterString is ignored at gate level (between operator
  and device password policy). New `AllowlistHashWithReinit
  States` (separator 0xFC) extends the v1.13-chunk-8 ladder;
  backwards-compat ladder degrades through chunks 8/7/v1.12-
  chunk-7/v1.4 when each dimension is empty. Refactor
  introduced helper `sortAllowedCreateObjects` and
  `writeReinitStatesBlock` to keep the new hash function under
  funlen; `runBACnetDryRun` extracted with a
  `bacnetDryRunInputs` struct so the dry-run command stays
  under gocyclo as we keep adding dimensions; `printBACnet
  DryRunSummary` + `parseBACnetServiceChoices` /
  `parseBACnetReinitStates` extracted as helpers. 11 new tests
  (4 hash ladder + 4 wire parser including out-of-range fail-
  closed + 5 e2e covering the canonical "coldstart refused
  when only activate-changes is allowed" safety invariant).
- 2026-04-25 — **v1.13 chunk 8 landed.** BACnet CreateObject
  (svc 10) per-type allowlist. Natural sequel to chunks 3 + 7
  in the BACnet sequence: chunk 3 closed WPM (svc 16), chunk 7
  closed DeleteObject (svc 11), chunk 8 closes the third
  destructive service. New CLI flag `--create-object-type N`
  (numeric BACnetObjectType, repeatable); YAML field
  `create_object_types:` (`{type}` only — no instance dimension).
  Wire parser at `internal/protocols/bacnet/wire/createobject.go`
  walks the BACnet ASN.1 BER form: 0x0E (open ctx tag 0
  constructed) + one of {0x09 1B / 0x0A 2B objectType, 0x1C 4B
  objectIdentifier} + 0x0F (close). The gate matches by type
  ONLY — even when the operator uses the [1] objectIdentifier
  CHOICE form (which encodes a specific instance), the
  instance is ignored at gate level. The typical BAS use-case
  is "allow creating new Schedule (type 17) objects" — type-
  level allowlist matches naturally. New
  `AllowlistHashWithCreateObjects` (separator 0xFD) extends the
  v1.13 chunk-7 ladder; backwards-compat ladder degrades
  through chunks 7/12-chunk-7/v1.4. **Separate list from both
  AllowedObjects and AllowedDeleteObjects** — property writes
  don't auto-grant creation, deletion privileges don't auto-
  grant creation. 13 tests (4 hash ladder + 6 wire parser + 5
  e2e gate including a "AllowedObjects entry doesn't auto-grant
  CreateObject" separation test). Refactor: extracted
  sortAllowedServices/Objects/DeleteObjects helpers + per-block
  hashWriter helpers to keep AllowlistHashWithCreateObjects
  under funlen; canonAllowFileBACnetCreateTypes extracted from
  buildAllowFileBACnet; applyBACnetAllowFile extracted from
  loadAllowFile.
- 2026-04-25 — **v1.13 chunk 7 landed.** BACnet DeleteObject
  (svc 11) per-target allowlist. Separate `AllowedDeleteObjects
  []{ObjectType, ObjectInstance}` list (kept distinct from the
  property-level `AllowedObjects` from v1.12 chunk 7 + v1.13
  chunk 3). The typical BAS pattern is "writes ok, delete
  forbidden", so an operator who allowed
  `--object type=2;instance=99;property=85` (write PresentValue
  on BinaryOutput#99) must explicitly add
  `--delete-object type=2;instance=99` to permit deletion.
  `ParseDeleteObject` reuses the v1.12 `readObjectID` helper
  (tag 0x0C + 4 bytes packed: 10-bit type<<22 | 22-bit
  instance). New `AllowlistHashWithDeleteObjects` (0xFE
  separator) extends the WPM hash; ladder degrades to v1.13/
  v1.12/v1.4 hashes when each successive dimension is empty.
  `--delete-object` flag, YAML `delete_objects:` field, 11
  tests. Commit `934c4f7`.
- 2026-04-25 — **v1.13 chunk 6 landed.** Triage `utility` bucket
  added as the 4th priority bucket (quick_win → strategic →
  utility → routine). Heuristic: severity ∈ {info, low} AND
  (Protocol ∈ {banner, atmodem} OR impact_class < 20).
  Captures findings that expose useful fingerprint info but
  aren't direct nails — old SSH banners, HTTP-HEAD with
  `Server: nginx/1.10`, AT modem chatter. `BucketUtility` const
  + `Summary.Utility []core.Finding`. `cmd/elsereno/cmd_explain.go`
  mirrors the heuristic locally + emits a `utility:` count
  line. `routine` items move down to `utility` when the
  heuristic fires; `quick_win` / `strategic` are never
  reclassified. Commit `20f6215`.
- 2026-04-25 — **v1.13 chunk 5 landed.** CWMP-over-TLS
  operator recipe (docs only). Three front-proxy patterns
  documented in `docs/protocols/cwmp.md`: nginx (`stream`
  module), HAProxy (`mode tcp`), Caddy (`layer4` plugin).
  Each terminates TLS on port 7548 and forwards plaintext to
  ElSereno's CWMP gate on 7547. The gate itself stays
  agnostic — TLS termination is the front-proxy's
  responsibility. Snapshot also covers the cert-rotation
  workflow + the operator-side cert-pinning recipe with curl.
  Commit `861aa8d`.
- 2026-04-25 — **v1.13 chunk 4 landed.** CWMP RPC-name
  case-warning in dry-run. TR-069 §A.4 declares RPC names
  case-sensitive. `emitCWMPRPCCaseWarnings` walks the
  user-supplied `--rpc <Name>` list against
  `canonicalCWMPRPCNames` (24 entries: 14 read-only +
  protocol-flow + 10 write-capable) and emits
  `WARN: --rpc "FactoryReset" — did you mean "factoryReset"?`
  for case-mismatches. The gate itself is unchanged (still
  case-sensitive); the warning is operator UX. Commit
  `861aa8d`.
- 2026-04-25 — **v1.13 chunk 3 landed.** BACnet
  WritePropertyMultiple (svc 16) per-object gate. WPM has a
  nested SEQUENCE-OF-WriteAccessSpecification structure where
  each spec contains an ObjectIdentifier + listOfPropertyValues.
  Each property value can be a CONSTRUCTED ASN.1 BER value
  (BACnetWeeklySchedule, BACnetDateRange, …). New
  `parseInnerPropertyValue` walks via depth-aware
  `skipUntilDepthZero`/`skipOneTagBody` helpers (any-depth
  constructed children + extended-length forms 0..4 inline +
  5 extended). `readInnerPropertyID` uses context tag 0
  (0x09/0x0A/0x0B) — different from WriteProperty's tag 1.
  Any single forbidden tuple in the listOfWriteAccessSpecifications
  refuses the WHOLE WPM batch (fail-closed multi-target gate
  analogous to the OPC UA WriteRequest walker). 10 tests.
  Commit `38dedff`.
- 2026-04-25 — **v1.13 chunk 2 landed.** CWMP firmware
  pre-flight verifier. New CLI verb
  `elsereno-offensive write cwmp verify-firmware
  --firmware url=…;sha256=…` resolves the URL via HTTP HEAD
  → GET, computes SHA-256 over the body, and compares against
  the operator-supplied pin. Output: `OK` / `MISMATCH` /
  `UNREACHABLE`. Useful before the operator pastes a
  firmware allowlist into `proxy listen` — catches typos /
  stale pins / supply-chain swaps. Constants
  `firmwareStatusOK`/`Mismatch`/`Unreachable` (goconst fix).
  6 tests. Commit `781ee50`.
- 2026-04-25 — **v1.13 chunk 1 landed.** InternetDB bulk
  lookup. v1.12 chunk 9 shipped single-IP lookups; this
  ships the bulk forms `internetdb:file:<path>` (one IP per
  line) and `internetdb:-` (stdin). `readInternetDBTargets`
  dispatches the three shapes (single / file / stdin);
  `lookupAllInternetDB` rate-limits at the upstream's ~10 rps.
  3 tests. Commit `781ee50`.
- 2026-04-25 — **doc hygiene chunk C** landed. TODO.md
  trimmed 203 → 65 lines (closed-checklist tone removed,
  brief delivery table added). TODO-vNext.md restructured
  with a `## ✅ Shipped during v1.3-v1.12` archive section
  + active items. ROADMAP.md gained "Shipped highlights
  post-v1.1" condensed lineup. New `man/src/man1/elsereno.1.md`
  (197 lines) — first man1 page covering default + offensive
  command sets, write-gate flag summaries, global flags,
  files, exit codes. `scripts/gen-manpages.sh` loop now
  `for section in 1 5 7` (was 5 7); dropped dead cobra/doc
  branch. 5 new per-protocol pages under `docs/protocols/`
  (sip, iax2, pbxhttp, cwmp, opcua). Commit `c581a62`.
- 2026-04-25 — **make sec ratchet fix.** Standalone gosec
  doesn't honour `//nolint:gosec` (golangci-lint convention);
  it only honours native `// #nosec G<NNN>` annotations.
  Swapped 18 markers across the codebase so `make sec` exits
  0. Commit `b611f5c`.
- 2026-04-25 — **v1.12.0 closed.** Ten-chunk cycle landed.
  Theme: gates tightening + input pagination. Each existing
  write-gated proxy gets a finer dimension; each existing
  attack-surface input client paginates; one new no-key
  provider (internetdb) joins the lineup; CWMP `Download`
  gets per-firmware-URL allowlisting. 100 new tests cycle-
  wide. Hash ladders preserve all prior tokens (operators
  who skip the new fields keep their v1.4–v1.11 confirm-
  tokens). 7 offensive write-gated proxies (unchanged), 6
  attack-surface input providers (up from 5). See
  `.context/snapshots/v1.12.0-gates-tightening-and-inputs.md`
  for the full breakdown. Commits: chunk 1 `1a6cec3`, chunk
  2 `0c34382`, chunk 3 `b4bd4dd`, chunk 4 `c3cafd1`, chunk 5
  `0325999`, chunk 6 `9b2c4f5`, chunk 7 `196e647`, chunk 8
  `8c61ff5`, chunk 9 `afb4eb3`, chunk 10 `9761eba`.
- 2026-04-25 — **v1.12 chunk 10 landed.** CWMP firmware-URL +
  SHA-256 allowlist for the `Download` RPC. Closes the firmware-
  push attack surface — a misconfigured ACS can push firmware
  to millions of devices, so per-image scoping is the natural
  v1.11→v1.12 tightening. Library:
  `AllowedFirmware{URL, SHA256}` + `canonicaliseFirmwareURL`
  (lowercases scheme+host, strips default ports `:80` for http
  / `:443` for https, preserves path+query verbatim) +
  `AllowlistHashWithFirmware` (0xFD separator below 0xFE
  param-paths; each entry is length-prefixed URL + length-
  prefixed SHA256) + `SessionMutationWithFirmware`. Hash
  ladder: empty firmware → chunk-1 hash; empty firmware AND
  empty paths → v1.11 hash. SHA256 is operator metadata only —
  TR-069's Download RPC doesn't carry it (the CPE reports it
  later via TransferComplete); the gate enforces URL only.
  Handler `AllowedFirmware` field + `firmwareGateActive(rpc)` +
  `firmwareURLAllowed(url)` + `extractDownloadURL(body)`
  (streaming xml.Decoder walking `<Download>` → `<URL>`).
  Refusal is SOAP Fault 9001 + `X-Elsereno-Gate-Reason: CWMP
  firmware URL not in session allowlist`. CLI:
  `write cwmp dry-run --firmware url=…;sha256=…` (sha256
  optional, validated as 64 lowercase hex) +
  `proxy listen --firmware` + YAML `firmware:` array with
  `{url, sha256}` entries. Refactor: `applyCWMPAllowFile`
  extracted from `loadAllowFile` (funlen);
  `cleanCWMPRPCs` + `cleanCWMPFirmware` extracted from
  `buildAllowFileCWMP` (gocyclo); `rpcNameDownload` const
  (goconst). 9 new tests: hash ladder × 6 (empty=chunk-1,
  empty-all=v1.11, non-empty changes, order-insensitive,
  url-case-insensitive, default-port-stripped), E2E gate × 4
  (allowed-passes, forbidden-refuses-9001, empty-bypasses,
  canonicalisation-matches), YAML round-trip × 1. 0 lint
  issues.
- 2026-04-25 — **v1.12 chunk 9 landed.** Shodan InternetDB
  (`internetdb.shodan.io`) wired as the 6th attack-surface
  input provider. Free + no API key required (the upstream is
  rate-limited to ~10 rps; the client defaults to 5 rps).
  Lookup-by-IP rather than search-by-query: operator gives
  `--input internetdb:8.8.8.8` and the package issues GET
  `/<ip>` → returns one core.Target per open port. New
  `internal/inputs/internetdb` package (doc.go +
  client.go). 404 from upstream maps to `(nil, nil)` (clean
  "no data" UX). Invalid-IP input fails with `ErrInvalidIP`.
  Dispatcher in `cmd_scan_apicreds.go` bypasses the creds-
  file check for this provider (the only no-key one). Single-
  IP only — bulk lookup (file or stdin) is a v1.13+ follow-up.
  5 new tests: happy path, 404-is-empty, invalid-IP rejected,
  500 surfaces as error, invalid ports dropped silently.
  Provider count: 6 — shodan / censys / fofa / zoomeye /
  onyphe / internetdb. 0 lint issues.
- 2026-04-25 — **v1.12 chunk 8 landed.** Input pagination across
  all 5 providers — closes the v1.10 "page 1 only" carry-over
  noted in 4 of the 5 client comments. New `SearchPaged(ctx,
  query, totalLimit)` method on each client. Per-provider:
  - Shodan: `?page=N` parameter; `searchPage` shared helper
    between `Search` (page 1) and `SearchPaged` (loop).
  - Censys: cursor follow via `links.next`; `searchPage` returns
    (hits, nextCursor); empty cursor terminates.
  - FOFA: `?page=N` (1-indexed); per-page size 100; partial-
    page detection.
  - ZoomEye: `?page=N` (1-indexed); ~20/page from server.
  - ONYPHE: `?page=N` (1-indexed); accumulates results.
  All loops stop on (a) totalLimit reached, (b) empty page,
  (c) ctx cancelled. CLI `readShodanTargets` /
  `readCensysTargets` / `readFOFATargets` / `readZoomEyeTargets`
  / `readOnypheTargets` switched to `SearchPaged` with a shared
  `providerTotalLimit = 1000` cap (free-tier sane default).
  9 new tests: Shodan × 3 (cap, empty-page, default-100),
  ZoomEye × 2 (accumulates, stops-on-empty), ONYPHE × 1
  (multi-page accumulation), FOFA × 1 (page increment),
  Censys × 2 (cursor follow, totalLimit cap). 0 lint issues.
- 2026-04-25 — **v1.12 chunk 7 landed.** BACnet per-object
  WriteProperty allowlist via ASN.1 BER parsing. Closes the
  v1.4 chunk 6 "service-choice only" carry-over for the most
  common BACnet write surface. New wire parser
  `ParseWriteProperty(apdu)` walks context tag 0 (ObjectId, 4
  bytes packed: 10-bit type + 22-bit instance) + tag 1
  (PropertyId, 1..3 bytes); ignores remaining tags (array index,
  value, priority) — gate decision needs only (type, instance,
  property). New library types `AllowedObject{ObjectType
  uint16, ObjectInstance uint32, PropertyID uint32}` +
  `AllowlistHashWithObjects` (0xFF separator below the v1.4
  service-choice block; per-entry: 2-byte type + 4-byte
  instance + 4-byte property = 10 bytes). Hash ladder: empty
  objects → v1.4 hash. `SessionMutationWithObjects` factory.
  Handler `AllowedObjects` + `writePropertyObjectAllowed`
  per-frame check that fires only on confirmed-service 15;
  other mutating services (10/11/16/17/20/27/8/9/7) bypass the
  per-object gate (their request shapes differ — v1.13+ work).
  Refusal is the existing security-error Abort-PDU. CLI:
  `write bacnet dry-run --object type=N;instance=M;property=P`
  (repeatable) + `proxy listen --object` + YAML `objects:` with
  structured `{type, instance, property}` entries. Sort order
  on emit: (type, instance, property). 13 new tests: hash
  ladder × 4, BER parser × 4 (happy path / multi-byte propid /
  truncated / wrong tag), E2E gate × 4 (allowed-passes /
  forbidden-property-refuses / forbidden-type-refuses /
  empty-list-bypasses), YAML round-trip × 1. 0 lint issues.
- 2026-04-24 — **v1.12 chunk 6 landed.** OPC UA per-CallMethod
  allowlist. Complements v1.12 chunk 3 (per-WriteValue NodeId)
  with the other mutating service surface: CallRequest invokes
  a Method on an Object; this gate scopes it to specific
  (ObjectID, MethodID) pairs. New wire walker
  `CallRequestAllMethods` parses the MethodsToCall array;
  InputArguments walker reuses chunk 2's `skipVariant` +
  wraps it with `skipVariantArray` for Variant[]. New library
  types `AllowedCallMethod{ObjectID, MethodID}` (both canonical-
  string NodeIds). Hash extension
  `AllowlistHashWithCallMethods` adds a 0xFC separator below
  the 0xFD / 0xFE / 0xFF blocks used by chunk 3 / v1.6 / v1.2;
  each entry is length-prefixed (uint16). Ladder: empty
  callMethods → chunk-3 hash; empty+empty → v1.6; empty×3 →
  v1.2. `SessionMutationWithCallMethods` factory + handler
  field `AllowedCallMethods`. Gate check
  `callRequestAllMethodsAllowed` fails closed on unparseable
  MethodsToCall. CLI: `write opcua dry-run --call-method
  object=…;method=…` (repeatable) + `proxy listen
  --call-method` + YAML `call_methods:` array with
  `{object, method}` entries. `parseCallMethodFlag` splits on
  `;method=` so the embedded `;` in each NodeId doesn't
  confuse the parser. 9 new tests: hash ladder × 4, wire
  walker × 4, E2E gate × 3 (allowed pass / one-forbidden
  refuse / string-NodeId match), YAML round-trip × 1.
  0 lint issues.
- 2026-04-24 — **v1.12 chunk 5 landed.** SIP From-header domain
  allowlist — the identity-spoof complement to v1.10 chunk 1's
  REGISTER AOR gate and v1.9 chunk 5's INVITE prefix gate.
  Library: `AllowedFromDomain{Domain}` + `AllowlistHashWithFromDomains`
  (0xFD separator layered on top of 0xFE AOR + 0xFF prefix) +
  `SessionMutationWithFromDomains`. Ladder preserved: empty
  fromDomains collapses to v1.10; empty+empty → v1.9; empty×3 →
  v1.4. `canonicaliseFromDomain` extracts the host part —
  accepts bare host, `@host`, `sip:user@host`, bracketed
  `<sips:user@host;tag=…>` — lowercases, strips params.
  Handler: `AllowedFromDomains` field checked in `checkSubGates`
  for every gated method (INVITE / REGISTER / MESSAGE /
  SUBSCRIBE / NOTIFY / REFER / PUBLISH / UPDATE / INFO).
  Always-safe methods (OPTIONS / ACK / BYE / CANCEL / PRACK)
  bypass the check. Refusal is SIP/2.0 403 Forbidden with
  `X-Elsereno-Gate-Reason: From domain not in session allowlist
  (identity-spoof guard)`. CLI: `write sip dry-run
  --from-domain` + `proxy listen --from-domain` + YAML
  `from_domains:` field (lowercased, sorted, deduped).
  Refactor: `AllowlistHashWithFromDomains` split across
  `sortedMethodList` / `sortedPrefixList` / `sortedAORList` /
  `sortedFromDomainList` / `writeNulTerminatedList` for funlen;
  `forwardOne` split with `checkSubGates` + `refusalWriter`
  type for gocyclo. 11 new tests: hash ladder × 5 (empty =
  v1.10, empty-all = v1.4, non-empty changes hash, order-
  insensitive, case-insensitive canonical), E2E × 4 (allowed
  INVITE passes, forbidden INVITE 403, OPTIONS bypasses,
  REGISTER also gated), YAML round-trip × 2 (case-
  normalisation + omit-when-empty). 0 lint issues.
- 2026-04-24 — **v1.12 chunk 4 landed.** Modbus structured
  `writes:` YAML closes the v1.9 chunk 2 carry-over. New YAML
  struct `proxyModbusWrite{Unit, FC, Start, End}` alongside the
  legacy `functions:` list; loader merges both into one
  `[]AllowedWrite`. CLI gains `--write unit=N;fc=M;start=A;end=B`
  (repeatable, validating: fc required; unit/start/end default
  to 0 = any). Emit-allow-file guard lifted — legacy
  `--function + --unit + --address-*` combinations now
  materialise as a `writes:` entry per FC so the gate tightening
  survives round-trip (previously refused with "not compatible"
  error). `parseModbusWriteFlag` refactored across
  `splitModbusWriteToken` + `applyModbusWriteKey` for
  gocyclo. 7 new tests: parser valid × 4 input shapes, parser
  invalid × 8 rejection cases, tight-gate round-trip, structured-
  write flag output, structured-write round-trip, hash-stable
  round-trip. Library hash unchanged — the existing
  `AllowlistHash` already sorted by (unit, FC, start, end), so
  operators who only used `functions:` keep their v1.9 tokens.
- 2026-04-24 — **v1.12 chunk 3 landed.** OPC UA String / GUID /
  ByteString NodeID encodings reach the per-node gate. Rich
  wire parser: `NodeIDValue{Namespace, Kind, Numeric, String,
  GUID, Bytes}` with `.Canonical()` returning `ns=N;{i,s,g,b}=…`.
  `WriteRequestAllNodesRich` walks every WriteValue with the
  rich parser (shared helper with v1.12 chunk 2 so only the
  per-entry shape differs). Handler gains
  `AllowedCanonicalNodeIDs []AllowedCanonicalNodeID` alongside
  the v1.6 numeric list; `richNodeIDAllowed` matches numeric
  wire values against the numeric list and canonical strings
  (uppercase hex for GUID / ByteString) against the canonical
  list. `AllowlistHashWithRichNodeIDs` extends the hash ladder
  with a 0xFD separator + length-prefixed canonical entries —
  empty canonical list collapses to the v1.6 hash, empty both
  collapses to v1.2. CLI `--node-id` accepts
  `ns=N;{s=STR,g=HEX,b=HEX}`: GUID tolerates dashes and
  normalises to uppercase hex; ByteString requires even hex.
  YAML schema gains a `canonical:` field on each `node_ids:`
  entry (numeric-only and canonical-only round-trip cleanly).
  17 new tests: 5 hash ladder + 5 rich wire parser + 4 E2E gate
  + 1 YAML round-trip + 2 CLI parse coverage. Closes the v1.6
  chunk 2 carry-over that fell through on non-numeric
  encodings. 0 lint issues after helper extractions
  (walkWriteRequestArrayPrefix, splitNodeIDTokens,
  buildParsedNodeID, applyOPCUAAllowFile).
- 2026-04-24 — **v1.12 chunk 2 landed.** OPC UA multi-node
  walk (`WriteRequestAllNodes`). Numeric encoding only; fails
  closed on any unparseable WriteValue.
- 2026-04-24 — **v1.12 chunk 1 landed.** CWMP per-parameter-
  path allowlist (`AllowedParameterPath{Prefix}` +
  `AllowlistHashWithParameterPaths` + SOAP Fault 9005 refusal).
- 2026-04-24 — **v1.11.0 closed.** Single-chunk cycle: CWMP
  offensive proxy (SOAP RPC allowlist). Completes the TR-069
  story — v1.4 chunk 5 shipped the fingerprint, this chunk
  ships the matching offensive gate. 7 offensive write-gated
  proxies in the default build (up from 6). `AllowedRPC{Name}`
  + `WriteGatedHandler.Allowed` + `AllowlistHash` +
  `SessionMutation` + `canonicaliseRPC` (strips cwmp:/cwmp-1-0:
  namespace prefix, case preserved per TR-069 §A.4).
  `alwaysSafeRPCs` set (14: GetParameter*, Inform,
  TransferComplete, Kicked, Fault, +Response variants).
  `extractRPCName` via streaming `xml.Decoder` — finds first
  `StartElement` under `<*:Body>`, handles `soap:`/`soap-env:`
  /`soapenv:` prefix variants. Refusal is HTTP 200 OK + SOAP
  Fault body FaultCode 9001 "Request denied" (TR-069 Annex A)
  + X-Elsereno-Gate-Reason header. 20 tests (13 library + 3
  YAML + 4 CLI). Snapshot:
  `.context/snapshots/v1.11.0-cwmp-offensive.md`.
- 2026-04-24 — **v1.10.0 closed.** Single-chunk cycle: SIP
  REGISTER AOR allowlist (anti-registration-hijack). Twin of
  v1.9 chunk 5's INVITE prefix gate — where that one controls
  WHERE calls can go, this controls WHO can register a
  binding. `AllowedAOR{AOR}` + `AllowlistHashWithAORs` +
  `SessionMutationWithAORs` + `canonicaliseAOR` (strips scheme
  / angle brackets / URI params; host lowercased, user part
  preserved per RFC 3261 §19.1.1). `registerAORAllowed`
  exact-match canonical compare; fail-closed on
  empty/malformed To:. `writeRegisterForbidden` emits 403 +
  X-Elsereno-Gate-Reason "AOR not in session allowlist
  (REGISTER hijack guard)". CLI: `write sip dry-run --aor` +
  `proxy listen --aor` + YAML `aors:`. Hash backwards-compat
  ladder: empty aors → v1.9; empty aors AND empty prefixes →
  v1.4. 15 tests (10 library + 5 YAML round-trip). Snapshot:
  `.context/snapshots/v1.10.0-sip-aor.md`.
- 2026-04-24 — **v1.9.0 closed.** Five-chunk cycle. Chunk 1
  closes the v1.6 per-NodeId → YAML round-trip gap (the
  `--allow-file` emitter + loader now persist `node_ids:`
  structurally). Chunk 2 adds `write modbus proxy-dry-run`,
  closing the write-surface asymmetry (now all 6 gated
  plugins have proxy-session dry-runs). Chunk 3 wires the 4
  input clients (Shodan/Censys/FOFA/ZoomEye) into
  `scan --input <provider>:<query>` with a 0600-enforced
  `--api-creds-file <path.yaml>` for credentials. Chunk 4
  adds ONYPHE (`internal/inputs/onyphe`) as 5th provider
  with bearer-auth header + OQL query syntax. Chunk 5
  extends the SIP write-gate with an opt-in INVITE
  destination prefix allowlist for concrete toll-fraud
  mitigation (e.g. allow INVITE but only to "+34"/"+44",
  block "+900" premium-rate). 33 new tests. Backwards
  compatible: empty allowlists / nil prefix lists preserve
  v1.4-v1.8 hashes and tokens. Snapshot at
  `.context/snapshots/v1.9.0-roundtrip-inputs-toll.md`.
  v1.9.0 tag signed locally.
- 2026-04-24 — **v1.9 chunk 5 (SIP INVITE To-URI prefix
  allowlist)** landed on main. Opt-in
  `WriteGatedHandler.AllowedToURIPrefixes` field. Hash is
  backwards-compat: empty prefix list returns the v1.4
  AllowlistHash. Per-request check parses the To: header's
  URI user-part (handles `sip:` / `sips:` / `tel:` schemes,
  display-name quoting, uri-params suffix); match against
  sorted prefixes. Refusal: `SIP/2.0 403 Forbidden` with
  `X-Elsereno-Gate-Reason:` header. REGISTER + other methods
  unaffected — prefix list gates INVITE only. CLI:
  `write sip dry-run --to-prefix +34`,
  `proxy listen --to-prefix +34`, YAML `to_prefixes:`.
  7 tests.
- 2026-04-24 — **v1.9 chunk 4 (ONYPHE input)** landed on
  main. 5th provider alongside Shodan/Censys/FOFA/ZoomEye.
  Bearer auth via `Authorization: bearer <key>` header (RFC
  6750). Query embedded in URL PATH (not query string) —
  `url.PathEscape` encodes. In-body error flag. 5 tests.
- 2026-04-24 — **v1.9 chunk 3 (input CLI wire-up)** landed
  on main. `scan --input shodan:<q>|censys:<q>|fofa:<q>|
  zoomeye:<q>` with `--api-creds-file <path.yaml>`. 0600
  perm enforcement at load. KnownFields strict. 1 rps per
  provider. 11 tests.
- 2026-04-24 — **v1.9 chunk 2 (Modbus proxy-session
  dry-run)** landed on main. New subcommand `write modbus
  proxy-dry-run`. --function (repeatable) + optional --unit
  + --address-from/--address-to. --emit-allow-file guard
  against YAML schema limitation. 6 tests.
- 2026-04-24 — **v1.9 chunk 1 (OPC UA NodeID YAML round-
  trip)** landed on main. proxyAllowFile gains NodeIDs
  field with yaml `node_ids:`. buildOPCUAHandler wires
  opts.nodeIDs → AllowedNodeIDs. buildAllowFileOPCUA
  serialises sorted NodeIDs. Existing v1.6 tests still
  pass. 4 new tests for round-trip.
- 2026-04-23 — **v1.8.0 PUBLISHED on GitHub Releases** as the
  first community release. Artefacts (4 platform tarballs + 4
  CycloneDX SBOMs + checksums.txt) built locally with
  goreleaser and uploaded via `gh release upload` after all
  CI release workflows failed at ~30s with "job not started
  because payment has failed / spending limit reached". The
  project shifts to the **GitHub free tier**: all 6 workflows
  (ci / release / codeql / supply-chain / benchmarks /
  nightly) gated to `workflow_dispatch:` only to stop
  accumulating billing failures. Verification flow is now
  **GPG-signed tag** (`git tag -v v1.8.0`, key
  ACE3B86BACACE7D6 — Daniel Solís Agea) + SHA-256 checksums
  + CycloneDX SBOMs. RELEASING.md rewritten to document the
  new flow with the legacy CI-based flow preserved at the
  bottom. Docs pass: elsereno-manual.md + .docx + cheatsheet
  + README all refreshed with 17-plugin table, proxy listen
  examples, `--allow-file` / `--emit-allow-file` usage, and
  FOFA/ZoomEye inputs (library-level).
- 2026-04-23 — **v1.8.0 closed.** Two-chunk cycle, operator-
  requested. Chunk 1 ships the FOFA (fofa.info) input client
  with email+key auth and qbase64 query encoding. Chunk 2
  ships the ZoomEye (zoomeye.org) input client with `API-KEY`
  header auth. Both library-level only (matches existing
  Shodan + Censys pattern); CLI wire-up is a v1.9 decision.
  10 new tests across the two packages. Snapshot at
  `.context/snapshots/v1.8.0-fofa-zoomeye-inputs.md`. v1.8.0
  tag signed locally.
- 2026-04-23 — **v1.8 chunk 2 (zoomeye input)** landed on main.
  `API-KEY` HTTP header auth (credentials don't leak via URL
  logs). 1-based paging. Envelope has top-level `ip` +
  nested `portinfo.port`. Rows with unparseable IP/port
  dropped silently. 5 tests including header-auth assertion +
  402 Payment Required path (free-tier credit exhaustion).
- 2026-04-23 — **v1.8 chunk 1 (fofa input)** landed on main.
  FOFA needs both email + API key (unlike Shodan's single
  key). Query base64-encoded per FOFA's `qbase64` convention.
  Requests `fields=host,ip,port` for stable row shape.
  `ErrNoCredentials` + `ErrAPIError` sentinels so callers
  distinguish auth/quota/bad-query from transport errors.
  5 tests including qbase64-round-trip assertion.
- 2026-04-23 — **v1.1.0 → v1.7.0 pushed to origin/main.**
  Operator restored PAT + ran `git push origin main` (41
  commits) + `git push origin v1.1.0 v1.2.0 v1.3.0 v1.4.0
  v1.5.0 v1.6.0 v1.7.0` (7 tags). 7 release workflows ran
  in parallel on GitHub Actions (goreleaser + cosign + GHCR
  + SBOM + SLSA attestation per tag).
- 2026-04-23 — **v1.7.0 closed.** Two UX chunks:
  chunk 1 added `write dry-run --emit-allow-file` to close the
  YAML round-trip introduced in v1.6 chunk 1. Chunk 2 added
  `write opcua dry-run` + `write bacnet dry-run` subcommands —
  OPC UA honours the v1.6 per-NodeId extension via `--node-id
  ns=N;i=M`. The write command surface is now symmetric across
  the five proxy-session-capable plugins (sip / iax2 / pbxhttp
  / opcua / bacnet). Modbus proxy-session dry-run is a v1.8+
  carry-over. Snapshot at `.context/snapshots/v1.7.0-yaml-
  round-trip.md`. v1.7.0 tag signed locally.
- 2026-04-23 — **v1.7 chunk 2 (write opcua/bacnet dry-run)**
  landed on main. `newWriteOPCUADryRunCmd` honours `--service
  <TypeID>` + optional `--node-id ns=N;i=M` for the v1.6 per-
  NodeId gate. `newWriteBACnetDryRunCmd` takes `--service-
  choice <N>`. Both emit the YAML allow-file via the v1.7
  chunk 1 emitter. `parseNodeIDFlag` + `canonUintList` +
  `canonNodeIDs` shared helpers. 7 new tests.
- 2026-04-23 — **v1.7 chunk 1 (write dry-run --emit-allow-
  file)** landed on main. `emitAllowFile(cmd, path, af)` with
  stdout vs file routing (0600 perms on file). `omitempty`
  YAML tags on proxyAllowFile so dry-runs don't emit empty
  per-plugin fields. 10 tests including a full emit → load →
  recover round-trip.
- 2026-04-23 — **TODO** note: FOFA (fofa.info) + ZoomEye
  (zoomeye.org) input integrations are operator-requested.
  Tracked in `TODO-vNext.md` under "Inputs + integraciones"
  alongside the existing ONYPHE / STIX 2.1 ideas.
- 2026-04-23 — **v1.6.0 closed.** Two chunks:
  chunk 1 added `--allow-file` YAML loader for `elsereno proxy
  listen` (single-file config instead of long flag lists).
  Chunk 2 added opt-in OPC UA per-NodeId allowlist — extends
  the v1.2 service-TypeID write gate with `AllowedNodeIDs`.
  Backwards-compatible: when the NodeID list is empty, the
  hash equals the v1.2 `AllowlistHash` so existing operator
  tokens remain valid. OPC UA is the first protocol gate with
  object-level granularity; BACnet + CallRequest per-object
  variants are v1.7+. Snapshot at
  `.context/snapshots/v1.6.0-allowfile-and-nodeid.md`. v1.6.0
  tag signed locally.
- 2026-04-23 — **v1.6 chunk 2 (OPC UA per-NodeId)** landed on
  main. New `internal/protocols/opcua/wire/writerequest.go`
  parses the UA RequestHeader + NodesToWrite array to extract
  the first WriteValue's NodeId for TwoByte / FourByte /
  Numeric encodings. Rarer encodings (String / Guid /
  ByteString) are structurally consumed but return ok=false so
  the caller fails closed. `offensive/write/opcua/gatedproxy.go`
  gains `AllowedNodeID{Namespace, Identifier}` type, an
  `AllowedNodeIDs` optional field on `WriteGatedHandler`, a
  new `AllowlistHashWithNodeIDs(target, services, nodeIDs)`
  that degrades to v1.2 hash for empty NodeIDs, and a second-
  stage `writeRequestNodeAllowed` check inside `routeFrame`.
  8 tests including 3 end-to-end gate tests (allowed NodeID
  forwards / blocked NodeID returns ServiceFault / empty
  allowlist falls back to v1.2 behaviour).
- 2026-04-23 — **v1.6 chunk 1 (--allow-file YAML)** landed on
  main. `elsereno proxy listen --allow-file <path.yaml>` reads
  the plugin + target + allowlist from a YAML file using
  `yaml.NewDecoder.KnownFields(true)` so typos fail noisily.
  Schema is per-plugin: `methods:` for sip, `subclasses:` for
  iax2, `allow:` for pbxhttp, `functions:` for modbus,
  `services:` for opcua, `service_choices:` for bacnet.
  Operator-supplied command-line flags act as defaults. 10
  tests (one happy-path per plugin + 4 error paths).
- 2026-04-23 — **v1.5.0 closed.** `elsereno proxy listen` CLI
  shipped. Two chunks: chunk 1 promoted the proxy stub to a
  real command supporting sip / iax2 / pbxhttp (with per-plugin
  `--method` / `--subclass` / `--allow` allowlist flags); chunk
  2 extended to modbus / opcua / bacnet (`--function` /
  `--service` / `--service-choice` flags) and added the first
  end-to-end integration test (fake SIP origin + real
  proxy.Server + real client assert that OPTIONS forwards and
  INVITE gets a 405 without upstream seeing it). 6 offensive
  write-gated proxies now runnable inline. v1.5.0 tag signed
  locally. Snapshot at
  `.context/snapshots/v1.5.0-proxy-listen.md`.
- 2026-04-23 — **v1.5 chunk 2 (proxy listen for modbus/opcua/
  bacnet + E2E)** landed on main. Extends chunk 1's sip/iax2/
  pbxhttp support to the three remaining gated plugins with
  numeric allowlist flags (range-validated uint8/uint16). Adds
  TestProxyListen_E2E_SIP — first full-stack test covering
  framework + handler + triple-confirm + filtering composed
  together. Splits buildGatedHandler into per-plugin
  constructors to keep gocyclo complexity ≤ 15.
- 2026-04-23 — **v1.5 chunk 1 (proxy listen)** landed on main.
  Promotes the cmd_stubs.go "proxy" command to a real offensive-
  build implementation: `elsereno proxy listen --plugin
  {sip|iax2|pbxhttp} --target h:p --listen L ...` authorises
  the gate via triple-confirm, binds a TCP listener, runs the
  protocol-specific handler inline via proxy.Server.Run until
  SIGINT/SIGTERM. replaceProxyStubWithOffensiveCmd walks the
  root command and replaces the EX_TEMPFAIL stub without
  touching the default build.
- 2026-04-23 — **v1.4.0 closed.** Offensive PBX write-gate
  cycle shipped: SIP method-allowlist gate (chunk 1), pbxhttp
  (method, path)-allowlist gate (chunk 2), IAX2 subclass-
  allowlist UDP gate (chunk 3), CLI dry-run wiring for all
  three (chunk 4), TR-069/CWMP ACS fingerprint plugin (chunk 5,
  plugin #17), BACnet/IP service-choice UDP gate closing the
  v1.2 carry-over (chunk 6). 4 new offensive write-gated proxies
  (bringing the total to 5: modbus/opcua/sip/iax2/pbxhttp/
  bacnet). Snapshot at
  `.context/snapshots/v1.4.0-offensive-pbx-and-cwmp.md`.
  v1.4.0 tag signed locally.
- 2026-04-23 — **v1.4 chunk 6 (BACnet UDP write-gate)** landed
  on main. `internal/protocols/bacnet/wire/service.go` ships
  ASHRAE 135 APDU classification (APDUType enum +
  ConfirmedService choices + IsMutatingConfirmedService
  predicate + BuildAbortPDU). `offensive/write/bacnet/
  gatedproxy.go` replaces the session-primitive stub with a
  full UDP relay: always-passes Who-Is / I-Am / acks / errors /
  non-BACnet / confirmed-reads; gates WriteProperty /
  WritePropertyMultiple / AtomicWriteFile / AddListElement /
  RemoveListElement / CreateObject / DeleteObject /
  ReinitializeDevice / DeviceCommControl / LifeSafetyOperation;
  refuses via BVLC-wrapped Abort-PDU with reason 5 (security-
  error). 14 tests.
- 2026-04-23 — **v1.4 chunk 5 (cwmp plugin)** landed on main.
  TR-069 / CWMP ACS fingerprint on 7547/tcp. 15 ACS vendor
  identifiers (GenieACS, FreeACS, Axiros, Nokia Altiplano,
  Huawei FusionHome, Broadcom BroadWorks, Cisco Prime, ADB,
  Friendly TR-069 Simulator, interaCMS, Netopia, create-net,
  open-ACS, TR-069 marker). VendorRisk tiers 90/85/75/80.
  isCWMPLikely heuristic fires on 401-with-acs-realm or
  SOAP-with-cwmp body even without vendor match. Default-build
  plugin count: 16 → 17. 15 tests.
- 2026-04-23 — **v1.4 chunk 4 (CLI dry-run for gated proxies)**
  landed on main. Three new cobra subcommands under `elsereno
  write`: `sip dry-run --method`, `iax2 dry-run --subclass`,
  `pbxhttp dry-run --allow METHOD:/path`. Each prints the
  canonicalised allowlist + SessionMutation PayloadHash; with
  --vault-passphrase-file also mints the expected confirm-
  token via confirm.ExpectedToken. 11 tests cover parseAllowEntry,
  iaxSubclassByName, canonMethods, cobra-driven shape checks,
  and --target-required behaviour.
- 2026-04-23 — **v1.4 chunk 3 (iax2 write-gate)** landed on main.
  UDP per-datagram subclass allowlist. Mini-frames (audio) +
  non-IAX frames (Voice/DTMF/Video) ALWAYS pass — media
  unconditional. Gated IAX subclasses: NEW / REGREQ / AUTHREP /
  ACCEPT. Refusal: HANGUP full-frame addressed to the client's
  SrcCallNum (the universal IAX call-teardown signal). 14 tests
  with net.Pipe UDP-semantics preserve-per-Write boundaries.
- 2026-04-23 — **v1.4 chunk 2 (pbxhttp write-gate)** landed on
  main. HTTP (method, path) allowlist via net/http's server
  parser. Read-only methods (GET/HEAD/OPTIONS) always pass;
  CONNECT always refused. Two-stage refusal: 405 when the
  method isn't in the allowlist, 403 when method matches but
  the path doesn't. 14 tests; bodyclose pitfall caught + fixed
  with a statusResp{Code, Header} snapshot helper.
- 2026-04-23 — **v1.4 chunk 1 (sip write-gate)** landed on main.
  Per-request method allowlist via net/textproto request-line
  parser. Always-safe set (OPTIONS/ACK/BYE/CANCEL/PRACK) passes
  unconditionally; gated methods (INVITE, REGISTER, MESSAGE,
  SUBSCRIBE, NOTIFY, REFER, PUBLISH, UPDATE, INFO) require
  explicit allowlist. Refusal: canonical SIP/2.0 405 Method
  Not Allowed with an Allow: header listing all permitted
  methods. 13 tests; gocyclo drove the Handle + handleOne split.
- 2026-04-22 — **v1.3.0 closed.** PBX-discovery cycle shipped:
  SIP + IAX2 + pbxhttp plugins (chunks 1a/1b/1c), 15 PBX brand
  fingerprints across the three, 16 plugins in the default
  build (up from 13 at v1.2.0). Snapshot at
  `.context/snapshots/v1.3.0-pbx-discovery.md`. Design patterns
  established: priority-ordered `{needle, vendor}` matcher
  tables (canonical template in `sip/vendor.go` +
  `pbxhttp/vendor.go`); 90/85/80/75/70 risk tiers by vendor
  class; protocol-native refusals on default proxies (SIP 403,
  IAX2 silent-UDP, HTTP 403); mini-frame length-sanity guard
  against HTTP-shaped bytes falsely confirming binary UDP
  protocols. v1.3.0 tag signed locally.
- 2026-04-22 — **v1.3 chunk 1c (pbxhttp plugin)** landed on main.
  HTTP(S) PBX admin-UI fingerprint on port 443 (also 80 / 8080
  / 8088 / 5001 / 8443 / 411 via Scheme override). 15 known
  PBX platforms identified via response Server / title / body:
  FreePBX, PBXact, 3CX, Yeastar (+ Linkus + NeoGate + MyPBX),
  Cisco UCM, Avaya (IP Office + Aura + Communication Manager),
  Mitel (+ ShoreTel + MiCollab), Grandstream (+ UCM6 + GXP +
  GXW), Fanvil, Yealink (+ SIP-T), Asterisk HTTP Manager,
  Switchvox, Elastix, FreeSWITCH. InsecureSkipVerify defaulted
  true — PBX default installs universally ship self-signed
  certs; fingerprinting use-case outweighs MITM risk (gosec
  waiver documented in code). PBX-likely heuristic: unmatched
  brand but body mentions pbx / phone system / sip server /
  voip admin / extension → protocol_risk=70 so the finding
  still surfaces. 21 tests; 15-vendor IdentifyVendor table;
  5-tier VendorRisk table. Offensive write-gated variant is a
  v1.4 candidate.
- 2026-04-22 — **v1.3 chunk 1b (IAX2 plugin)** landed on main.
  Asterisk's native binary UDP protocol on port 4569.
  `internal/protocols/iax2/wire/` is a minimal RFC 5456 full-
  frame parser (12-byte header, FrameType + IAXSubclass enums,
  BuildNEW + BuildHANGUP). Probe sends a bare NEW, classifies
  the reply by subclass: ACCEPT / AUTHREQ / REJECT / HANGUP /
  PING-PONG / REG* → iax2-* note + protocol_risk=90
  (Asterisk-specific; public-internet exposure is a direct
  PBX disclosure). ACCEPT triggers a polite HANGUP so the
  remote dialogue table doesn't grow. Mini-frame-length-
  mismatch guard prevents HTTP bytes (byte[0]=0x48 → high bit
  0 → looks like a mini-frame) from falsely confirming IAX2.
- 2026-04-22 — **v1.3 chunk 1a (SIP plugin)** landed on main.
  OPTIONS probe on port 5060 UDP+TCP identifies 15 known PBX
  brands from the Server / User-Agent response header:
  Asterisk, FreePBX, 3CX, Cisco UCM, Cisco SIP Gateway, Mitel,
  Avaya, Yeastar, Grandstream, Fanvil, Yealink, Kamailio,
  OpenSIPS, FreeSWITCH, SER. protocol_risk 70-90 per vendor
  class (attack-ripe 90, enterprise 85, SOHO 80, proxies 75,
  unknown 70). capability=60 once SIP confirmed; auth_state
  drops to 50 on a 401 response. DenyAll proxy emits a SIP
  403 Forbidden. Offensive write-gated variant v1.4.
- 2026-04-22 — **v1.2 chunk 5 (SLSA .intoto.jsonl fix)** landed
  on main. Dropped the `slsa-framework/slsa-github-generator`
  reusable workflow (upstream exit-27 bug, tracked since
  v2.0.0 and still unfixed in v2.1.0 — issue 2610). Replaced
  with GitHub's native `actions/attest-build-provenance@v2`:
  the release workflow now attests every `dist/elsereno_*.tar.gz`
  + `checksums.txt` with a SLSA v1.0 predicate signed via
  Sigstore keyless (same identity proof, same transparency log,
  no reusable-workflow dependency). Consumers verify with
  `gh attestation verify <artifact> --repo RobinR00T/elSereno`
  or `cosign verify-attestation --type slsaprovenance1 …`.
  `release.yml` gains `attestations: write` perm; drops the
  `slsa-provenance` + `slsa-provenance-gate` jobs; the hashes
  stage is also gone (no longer needed). SUPPLY-CHAIN.md +
  `.goreleaser.yml` footer + `scripts/release-smoke.sh` all
  updated with the new verify recipe.
- 2026-04-22 — **v1.2 chunk 4 (dial backends)** landed on main.
  New package `offensive/dial/backend` with the `Backend`
  interface (`Name` / `Deliver(ctx, normalised) → Result` /
  `Close`) + shared `Disposition` enum (preview, delivered,
  no-answer, busy, hangup, failed). Two concrete backends
  ship:
    * `Mock` — records intent, returns preview by default,
      scripted prefix-match dispositions for tests. Safe for
      CI + dry-runs.
    * `ATModem` — drives a Hayes-compatible modem over any
      io.ReadWriter. Wire sequence ATZ → ATE0 → ATDT<num>; →
      classify terminal result (CONNECT / NO ANSWER / BUSY /
      NO CARRIER / NO DIAL TONE / ERROR / timeout) → ATH0.
      Context-aware read (goroutine + select) so an
      unresponsive modem hits dialTimeout instead of
      hanging indefinitely. Shared bufio.Reader across the
      sequence prevents the classic "fresh reader discards
      read-ahead bytes" serial bug. No direct serial-fd
      open — callers pass the opened port so tests use
      net.Pipe.
  7 unit tests + 1 tri-phase modem simulator: each Hayes
  result code mapped to the right disposition, timeout path
  validated. VoIP SIP backend is declared in the package
  docstring as a separate subprocess binary (v1.3) because
  the seccomp dial profile blocks socket() in the parent.
  The `dial batch` CLI wiring to call Deliver on allowed
  numbers ships in the v1.2 close commit.
- 2026-04-22 — **v1.2 chunk 3 (protocol Handle loops)** landed
  on main: full wire-level `Handle` loops + protocol-native
  refusal frames for 5 TCP protocols that previously had only
  session primitives. Each handler parses the wire framing,
  matches against an allowlist, and either forwards or emits a
  refusal:
    * DNP3 (`handle.go`): link-layer primary + app-layer FC
      gating; refusal = user-data response with IIN2 bit 2
      FUNC_NOT_SUPP set. Read (FC 0x01) always passes.
    * IEC-104: APCI I/U/S type split; I-frames consult ASDU
      Type ID allowlist; refusal = I-format ACT_CON with
      COT=47 (negative confirm) mirroring the request's type.
    * HART-IP: SessionInitiate / Close / KeepAlive pass;
      TokenPassPDU inspects the embedded HART command byte
      (long or short frame); reads (cmd 0..3) pass; refusal =
      HART response with "command not implemented" response-
      code bit 0x40.
    * ATG Veeder-Root: line-oriented ASCII; 'I' info commands
      pass; others consult allowlist; refusal = Veeder-Root
      NAK (`<SOH>9999FF1B<CR><ETX>`).
    * Fox (Niagara): line-oriented; hello/get/list/a verbs
      always pass; refusal = `fox a 0 -1 fox denied\n`.
  BACnet stays at session-primitives-only because it's UDP and
  the generic TCP proxy doesn't apply; full BACnet relay lands
  in v1.3 with a dedicated UDP relay. 24+ unit tests total
  across the 5 packages exercising forward/refuse paths.
- 2026-04-22 — **v1.2 chunk 2 (OPC UA write gating)** landed
  on main. Extends `internal/protocols/opcua/wire/` with
  service-layer parsing: OPN/MSG/CLO header types,
  `ServiceTypeID` that decodes the TypeID from a MSG body's
  ExpandedNodeId (TwoByte / FourByte numeric in ns=0),
  `IsMutatingService` that returns true for
  WriteRequest (673) + CallRequest (704). New package
  `offensive/write/opcua` with `AllowedService{TypeID}`,
  `AllowlistHash` (order-insensitive), `SessionMutation`,
  `WriteGatedHandler.Authorise` + `Handle`. HEL/OPN/CLO pass
  through; MSG frames with non-mutating TypeIDs pass;
  mutating TypeIDs outside the allowlist get a UA-native
  ServiceFault reply (StatusCode BadUserAccessDenied =
  0x80100000) so real clients parse the refusal cleanly. 9
  tests: AllowlistHash determinism + target-sensitivity,
  Authorise happy path + denied token, routing (HEL passes,
  Read passes, Write refused on empty allowlist, Write allowed
  on match, Call treated like Write), Handle precondition.
  Full UA binary encoding of WriteValue / CallMethodRequest
  (per-NodeId allowlisting) is a v1.3 carry-over — the v1.2
  gate is at TypeID granularity.
- 2026-04-21 — **v1.2 chunk 1 (DB-backed panels)** landed on
  main. Three layers:
  1. `internal/audit.DBWriter` persists audit entries to
     Postgres with the same chain invariant as `FileWriter`.
     Reserves IDs via `nextval('audit_log_id_seq')` before
     INSERT so the hash is computed once and never rewritten.
     `MultiWriter` + `FileMirror` + `DBMirror` let operators
     fan-out to both sinks while a single Writer owns the
     chain (append-verbatim path on each mirror).
  2. New `internal/repo` package holds the read-side data
     access. `ListFindings` (cursor-paginated, filters on
     severity/protocol/min_score/created_after, clamped
     limit), `ListRuns` (status filter + correlated finding
     counts), `Triage` (per-severity tally). Every function
     takes a narrow `Querier` interface so unit tests use an
     in-memory fake instead of a live Postgres.
  3. Three new HTTP handlers — `GET /api/v1/findings`,
     `/runs`, `/triage` — rendered through `handlers.APIV1`'s
     new optional-deps bundle. Unwired endpoints return 503,
     the dashboard renders "backend unavailable" in that
     case. `serve` opens an optional pool when
     `DATABASE_URL` is set; missing DB simply disables the
     DB-backed endpoints and the rest of the server still
     runs. Three new dashboard panels (triage chips,
     findings table, runs table) fetch on page load +
     every relevant SSE signal (finding / run_start /
     run_end), debounced 500 ms.
- 2026-04-21 — **v1.1 chunk 8 (Wardialing batch)** landed on
  main: `offensive/dial/batch.go` classifies a list of numbers
  against the ADR-041 dial guard (normalise → ≤3-digit hard
  block → scope.blocked_numbers) and appends one
  `offensive_dial` audit entry per decision. New
  `elsereno dial batch --numbers-file <path> --scope
  <scope.yaml>` CLI verb (stdin when `--numbers-file` is omitted)
  installs the seccomp `dial` profile before classification and
  prints a per-decision tally + the audit path. Existing single-
  number check preserved as `elsereno dial validate`. Default
  disposition is "preview" (audit-only dry-run); actual PSTN /
  VoIP delivery lands with v1.2's modem / VoIP backends. E2E
  verified: 5-number input → 3 allow / 2 short, audit chain
  verified with `audit verify-file`.
- 2026-04-26 — **v1.15.0 PUBLISHED on GitHub Releases**
  (https://github.com/RobinR00T/elSereno/releases/tag/v1.15.0).
  9 assets (4 archives + 4 CycloneDX SBOMs + checksums.txt).
  Tag GPG-signed with `ACE3B86BACACE7D6`. Free-tier flow
  (goreleaser local + `gh release create`). Cycle-close
  commit `51572f2`; v1.15.0-released memory commit `27422dd`.
- 2026-04-26 — **ROADMAP.md drift purge.** Post-v1.15.0
  hygiene pass: deleted obsolete `🔴 v1.0.1 release-surface
  polish (queued)` section + its legend entry; deleted
  `v1.13/v1.14 cycle closed (tag pending)` per-chunk lists
  (snapshots have the breakdown; both shipped & released);
  renamed `v1.15+ proposed backlog` → `v1.16+ proposed
  backlog` and dropped shipped items (SIGHUP reload,
  `discover --auto <CIDR>`, STIX 2.1 export); added
  in-process allow-file reload as a v1.16+ candidate
  (alternative to v1.15 chunk-5 supervisor pattern); flipped
  v1.15 line in "Shipped highlights" from "Tag pending
  operator" → "Released on GitHub". Rewrote bottom priority
  matrix from "next 90 days" to "v1.16+ horizon": dropped
  `Cut v1.0.1` + the v1.1 P1/P2 rows (DB writer, SSE,
  WriteGatedHandler, GHCR, seccomp, OPC UA — all shipped);
  dropped P3 STIX 2.1 export (shipped); added P0 operator
  rows (revoke bootstrap PAT, restore GH Actions billing).
  Net: `-107 / +34` lines on ROADMAP.md. context-check ok.
- 2026-04-26 — **TODO-vNext.md + protocols/bacnet.md drift
  purge.** Second hygiene pass: rewrote `TODO-vNext.md`
  end-to-end. Last-refresh 2026-04-25 (post-v1.12) →
  2026-04-26 (post-v1.15). `## ✅ Shipped during v1.3–v1.12`
  → `v1.3–v1.15` with 9 new entries (BACnet svc 7/8/9/10/17/
  20/27 closures, IPv6 cross-cutting, CWMP TransferComplete
  observer-half, `discover --auto <CIDR>`, STIX 2.1, audit
  flock, SIGHUP supervisor variant). Section `🎯 High-leverage
  — siguiente ciclo (v1.13)` (4 items, all shipped) → `(v1.16)`
  (3 items: CWMP SHA-256 mismatch audit, BACnet per-instance
  Create + per-object LSO refinements, in-process allow-file
  reload as alternative to v1.15 chunk-5 supervisor pattern).
  Removed shipped items from "Herramientas operativas"
  (discover, triage utility, SIGHUP), "Supply-chain"
  (audit cross-process merge — replaced with optional
  `audit serve` daemon UDS as v1.16+), and "Plataforma"
  (STIX 2.1). Updated Windows-support note to reference v1.15
  chunk-4's `flock_windows.go` stub. Also bumped
  `.context/protocols/bacnet.md` per-object-LSO note + 2
  source-comment annotations (`internal/protocols/bacnet/wire/
  lifesafetyoperation.go`, `cmd/elsereno/cmd_proxy_allowfile_
  offensive.go`) from "v1.14+ if asked" → "v1.16+ if asked".
  Builds (default + offensive) green; context-check ok.
- 2026-04-26 — **v1.16 chunk 1 landed.** CWMP TransferComplete
  authorisation cross-reference (`33284c8`). Closes the v1.15
  chunk-1 observer half by correlating CPE → ACS
  TransferComplete envelopes with the prior Download
  authorisation. New `DownloadAuthorisation` struct exposed
  on `TransferCompleteFields.Authorisation`; `Outcome()`
  classifies into `succeeded` / `failed` / `orphan_complete` /
  `orphan_fault`. Default CLI observer log line gains
  `outcome=` / `download_url=` / `allowlist_sha256=` /
  `authorised_at=` fields. FIFO-bounded
  `pendingDownloads` map keyed by CommandKey, default cap 256.
  Resolution is one-shot (replayed TC sees nil
  Authorisation). 9 new tests across
  `transfercomplete_test.go` (E2E flows) +
  `pendingdownload_test.go` (unit tests).
- 2026-04-26 — **v1.16 chunk 2 landed.** BACnet per-(type,
  instance) CreateObject scoping refinement (`83a4b69`).
  Refines the v1.13 chunk-8 per-type list with a parallel
  per-(type, instance) list for the [1] objectIdentifier
  CHOICE form. New separator `0xF7` +
  `AllowlistHashWithCreateObjectInstances` +
  `SessionMutationWithCreateObjectInstances`. Wire parser
  extended via `ParseCreateObjectWithInstance` returning
  `(objType, instance, hasInstance, ok)`. Match precedence:
  per-instance match wins; falls back to per-type list.
  Operators wanting strict per-instance scoping leave per-
  type empty. CLI: `--create-object-instance type=N;
  instance=M`. YAML round-trip via
  `create_object_instances:`. Refactor: shared
  `parseBACnetTypeInstance` helper unifies --delete-object +
  --create-object-instance parsing (with named constants
  `bacnetKeyType` / `bacnetKeyInstance`). 9 new tests
  (`createobjectinstance_test.go`).
- 2026-04-26 — **v1.16 chunk 3 landed.** BACnet
  per-(operation, type, instance) LifeSafetyOperation
  scoping refinement (`ed98c71`). Refines the v1.13 chunk-11
  per-operation list with a per-target list for the optional
  [3] objectIdentifier. Operationally important on fire-alarm
  panels: "may unsilence LifeSafetyPoint #3 only" is much
  tighter than "may unsilence anything on this device". New
  separator `0xF6` + `AllowlistHashWithLSOTargets` +
  `SessionMutationWithLSOTargets`. Wire parser extended via
  `ParseLifeSafetyOperationWithTarget` returning
  `(op, target, hasTarget, ok)`. Match precedence: per-target
  match wins; falls back to per-op list. CLI: `--lso-target
  op=N;type=N;instance=N`. YAML round-trip via
  `lso_targets:`. Refactor: extracted `parseBACnetProxyOpts`
  + `buildBACnetServiceList` from `buildBACnetHandler` to
  keep it under funlen. 9 new tests (`lsotarget_test.go`)
  including the "HOSTILE silence attempted on Reset-only
  target" case.
- 2026-04-27 — **v1.16 chunk 4 landed.** BACnet
  token-generation cookie (`c3256da`) — foundation for
  in-process allow-file reload. New optional `Generation
  uint32` field on `bacnet.Allowlists` + `TokenGeneration
  uint32` on `bacnet.WriteGatedHandler` folds into the
  session hash via new separator `0xF5`. Operators bump the
  generation when editing the allow-file; a stale confirm-
  token (minted at the prior generation) is rejected at
  `Authorise()` time. New `AllowlistHashWithGeneration` /
  `SessionMutationWithGeneration` at the new top of the
  BACnet ladder; `Generation=0` (default) preserves every
  v1.4 → v1.16-chunk-3 confirm-token. CLI:
  `--token-generation N` on `proxy listen --plugin bacnet`
  + `write bacnet dry-run`. YAML round-trip via
  `token_generation:` field. 7 new tests
  (`tokengeneration_test.go`) covering hash distinctness,
  determinism, and the E2E Authorise stale-rejected /
  fresh-accepted / chunk-3-backwards-compat matrix. The
  actual reload signal handler + atomic allowlist swap are
  v1.17+ (chunk 4 ships only the cryptographic foundation).
  Cross-protocol parity (sip / iax2 / pbxhttp / modbus /
  opcua / cwmp gaining the field) follows incrementally if
  operators ask.
- 2026-04-27 — **v1.17 chunk 1 landed.** CWMP token-generation
  cookie + shared `--token-generation` flag promoted to the
  session-flag registrar (`ed868af`). Separator 0xFC (below
  0xFD firmware, 0xFE paths) at the top of the CWMP hash
  ladder. New `TokenGeneration uint32` field on
  `cwmp.WriteGatedHandler`. Refactor: shared
  `parseBACnetTypeInstance` helper (drops 40+ lines of
  duplication). 7 new tests (`tokengeneration_test.go`).
- 2026-04-27 — **v1.17 chunk 2 landed.** SIP token-generation
  cookie (`59ff0a2`). Separator 0xFC (below 0xFD fromDomains).
  `buildAllowFileSIP` signature gains trailing
  `tokenGeneration uint32`; 5 existing call sites updated.
  7 new tests.
- 2026-04-27 — **v1.17 chunk 3 landed.** Token-generation
  cookie roll-out across remaining 4 plugins (modbus / iax2
  / pbxhttp / opcua). Completes cross-protocol parity — every
  offensive write-gated proxy now carries the
  `--token-generation N` cookie surface. Separators 0xFC for
  modbus/iax2/pbxhttp; 0xFB for opcua (below the 0xFC
  callMethods layer). 14 buildAllowFile* call sites updated
  in cmd_write_emitfile_offensive_test.go for the new
  trailing argument. Refactor: `loadAllowFile` consolidates
  per-plugin token-gen blocks into one shared assignment
  (gocyclo 17 → under 15); `AllowlistHashWithGeneration` in
  opcua extracts `canonOPCUAAllowlist` for funlen;
  `buildAllowFileOPCUA` extracts
  `canonAllowFileOPCUACallMethods` +
  `canonAllowFileOPCUANodeIDs` for gocyclo. 20 new tests
  across 4 test files.
- 2026-04-27 — **v1.17 chunk 4 landed.** SIGUSR1 in-process
  allow-file reload + atomic swap. New `reloadableHandler`
  (atomic.Pointer wrapper), `--reload-allow-file` flag
  (requires --allow-file), sidecar `<allow-file>.token`
  (0600) for fresh confirm-token, `performReload` re-loads +
  rebuilds + authorises + atomic-swaps. Co-exists with v1.15
  chunk-5 SIGHUP supervisor-restart pattern: SIGHUP still
  exits 75; SIGUSR1 reloads in-place. Refactor: extracted
  `runProxyServer` from `runProxyListen` for funlen. 11 new
  tests (cmd_proxy_reload_offensive_test.go) covering
  wrapper delegation, atomic-swap semantics, sidecar-token
  mode enforcement, validation, fresh-opts immutability, and
  pass-through for non-reload runs.
- 2026-04-27 — **v1.17 chunk 5 landed.** `proxy_allowlist_
  reload` audit event (`02fef1e`) + migration `00003_*`.
  Every SIGUSR1 reload firing emits a row with status
  (`ok`/`failed`), plugin, target, allow_file, old/new
  hash-prefix, token_generation, and reason (on failure).
  Audit emit is best-effort — a failed audit-chain write
  doesn't block the swap. The internal/audit/events_test.go
  migration-sync test picks up the new event automatically.
  2 new tests (defensive nil-writer no-op + hash-prefix
  stability).
- 2026-04-27 — **v1.17 cycle closed on `main`** (5 chunks,
  tag pending operator decision). Snapshot:
  `.context/snapshots/v1.17.0-token-generation-and-in-process-reload.md`.
  v1.16 cycle also closed (4 chunks); v1.15.0 still the
  latest published release.
- 2026-04-27 — **v1.18 chunk 1 landed.** Dashboard CSV export
  from UI (`cc157d4`). New `?format=csv` query param on
  `GET /api/v1/findings` returns RFC-4180 CSV with
  Content-Disposition attachment + filename
  `findings-<RFC3339>.csv`. Columns: id, run_id, target_id,
  protocol, severity, score, created_at (RFC3339Nano UTC),
  factors (`name=value;…` semicolon-separated, factor names
  sorted alphabetically for stable diffs). Dashboard Findings
  panel gains a "Download CSV (top 500)" link. Backwards
  compat: no format param → JSON envelope (v1.2). 3 new
  tests.
- 2026-04-27 — **v1.18 chunk 2 landed.** Dashboard diff
  between runs (`1225312`). New
  `GET /api/v1/findings/diff?old=&new=` returns categorised
  envelope with three buckets (`new` / `resolved` /
  `persisting`); match key (target_id, protocol). New
  `repo.DiffFindings` + `repo.FindingsQuery.RunID` filter.
  Dashboard gains "Diff between runs" panel with two-input
  form + per-bucket result tables. 9 new tests (6 in repo
  unit + 4 in HTTP handler).
- 2026-04-27 — **v1.18 cycle closed on `main`** (2 chunks,
  tag pending operator decision). Snapshot:
  `.context/snapshots/v1.18.0-dashboard-csv-export-and-run-diff.md`.
  v1.17 + v1.16 cycles also closed; v1.15.0 still the latest
  published release.
- 2026-04-28 — **v1.19 chunk 1 landed.** Audit log API
  endpoint + dashboard panel. New
  `GET /api/v1/audit?event_type=&actor=&occurred_after=&
  limit=` returns the newest 50 (clamped [1, 500]) audit
  entries; new
  `GET /api/v1/audit/cadence?event_type=&days=N` returns
  per-day counts (clamped [1, 90]). New `internal/repo/
  audit.go` with `AuditEntry` / `AuditQuery` /
  `ListAuditLog` / `ListAuditCadence`. Tombstoned rows
  (audit-purge per ADR-013) come back with `payload=null` +
  `tombstoned=true`. Dashboard gains "Audit feed" panel with
  event_type dropdown + actor filter + payload-excerpt
  rendering (`[redacted]` for tombstoned). 6 new tests.
- 2026-04-28 — **v1.19 chunk 2 landed.** Reload cadence
  dashboard panel (`d2ebb0f`). Surfaces v1.17-chunk-5
  `proxy_allowlist_reload` audit rows as a per-day text-
  based bar chart (last 7 days). Pure dashboard; reuses
  chunk-1's `/api/v1/audit/cadence` endpoint. No new tests
  (chunk-1's TestAuditCadence_HappyPath already covers the
  underlying contract).
- 2026-04-28 — **v1.19 chunk 3 landed.** CWMP
  TransferComplete async firmware re-fetch. Closes the
  v1.16-chunk-1 loose end. Opt-in via
  `--verify-firmware-on-complete` (default off) +
  `--verify-firmware-timeout` (default 5m). On every
  successful TransferComplete carrying a resolved
  Authorisation with non-empty AllowlistSHA256, the proxy
  spawns a goroutine that re-fetches AllowlistURL, hashes
  the body, compares against AllowlistSHA256, emits a
  `cwmp_firmware_verify` audit row with status `match` /
  `mismatch` / `unreachable`. New `audit.EventCWMPFirmware-
  Verify` const + migration `00004_*`. Reuses
  `fetchFirmwareSHA256` from v1.13 chunk 2. 9 new tests
  covering classifier + observer-skip cases + opt-in/opt-
  out switch.
- 2026-04-28 — **v1.19 cycle closed on `main`** (3 chunks,
  tag pending operator decision). Snapshot:
  `.context/snapshots/v1.19.0-observability-completion.md`.
  v1.16 / v1.17 / v1.18 cycles also closed; v1.15.0 still
  the latest published release.
