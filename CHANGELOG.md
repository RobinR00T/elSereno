# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.56.0] — 2026-05-05

### Added

- **M-Bus offensive write-gated proxy on TCP/10001**
  (`-tags offensive`). Closes the v1.32+ D2
  carryover. Two-tier gate: control field (only
  SND_UD is mutating; SND_NKE/REQ_UD1/REQ_UD2/ACK
  always pass) + per-(CI, Address) tuple inside
  SND_UD with wildcards (CI=0 any CI, Address=0 any
  address). Empty `AllowedSNDUD{}` matches nothing
  (typo guard against {0,0}-as-wildcard).
- `internal/protocols/mbustcp/wire/control.go` (new):
  Control + CI catalogue + ReadFrame stream parser
  for M-Bus over TCP. Handles short / long / ACK
  frames with full bound-checking and checksum
  verification. `Frame.IsSNDUD()` +
  `Frame.IsAlwaysSafeControl()` classifiers.
- `offensive/write/mbustcp/gatedproxy.go` (new):
  WriteGatedHandler + AllowlistHash. Refusal mode
  is silent drop — M-Bus has no permission-denied
  frame, client retransmits and times out cleanly.

### Tests

`+25 tests` (10 wire + 15 gate).

### Build

3-variant matrix unchanged. Default build
behavioural unchanged. INSTALL.md unchanged (CLI
flag plumbing is a future cycle's add).

## [1.55.0] — 2026-05-05

### Added

- **KNX offensive write-gated proxy on UDP/3671**
  (`-tags offensive`). Closes the v1.32+ D1
  carryover. Three-tier gate: service-type (always-
  safe set covers discovery + keep-alive + ack +
  diag flow-control), APCI (Read/Response always
  pass inside TUNNELLING; write APCIs require
  allowlist), group-address (per-(GA, mask) ranges,
  operator picks granularity 0xFFFF/0xFF00/0xF800).
  Refusal mode is silent drop — KNXnet/IP has no
  "permission denied" service-type and a fabricated
  DISCONNECT could tear the wrong session.
- `internal/protocols/knxip/wire/services.go` (new):
  cEMI L_Data parser + 15 service-type constants +
  6 APCI constants + 6 cEMI Message Codes. Exposes
  `ParseTunnellingCEMI` (TUNNELLING_REQUEST shape)
  and `ParseCEMILData` (raw L_Data, used for
  ROUTING_INDICATION). `FormatGroupAddress` renders
  the 5/3/8-bit "main/middle/sub" canonical form.
- `offensive/write/knxip/gatedproxy.go` (new):
  AllowedService + AllowedAPCI + AllowedGroup with
  `Matches(dest)` mask semantics. AllowlistHash
  separators 0xE1 (APCI dimension) + 0xE2 (group
  dimension). UDP-aware WriteGatedHandler mirrors
  the iax2 ADR-040 template.

### Fixed

- **KNX service-type values for DESCRIPTION pair.**
  v1.21 chunk 1 had `ServiceTypeDescriptionRequest =
  0x0204` and `ServiceTypeDescriptionResponse = 0x0205`;
  KNX Standard 03.08.02 §4.1 specifies 0x0203 and
  0x0204. Real KNX hardware would have refused the
  request. The bug was masked because the wire test
  fixture used the same wrong values. Plugin
  fingerprint validation against real hardware will
  now pass.

### Tests

`+24 tests` (9 wire + 15 gate).

### Build

3-variant matrix unchanged. Default build sees no
behavioural change (offensive code is build-tag
gated). INSTALL.md unchanged (CLI flag plumbing is a
future cycle's add — same pattern as v1.52/v1.53).

## [1.54.0] — 2026-05-05

### Added

- **Beckhoff TwinCAT ADS plugin** (read-only
  fingerprint, TCP/48898). Closes the v1.32+ C
  carryover. Most-requested missing fingerprint since
  v1.25 closed the legacy-ICS trio. TwinCAT runs on
  Beckhoff CXxxxx IPCs, IPCxxxx, embedded controllers,
  EtherCAT couplers and BC bus terminals.
- `internal/protocols/twincat/wire/wire.go` (new):
  AMS/TCP framing (6-byte header) + AMS routing header
  (32-byte) + ReadDeviceInfo (cmd 0x0001) request
  builder + response parser. 4 sentinels.
  `BuildReadDeviceInfo(targetNetID)` constructs the
  38-byte request frame; `ParseDeviceInfo(buf)`
  validates framing and extracts version + 16-byte
  NUL-padded device-name string.
- `internal/protocols/twincat/twincat.go` (new):
  Plugin with operator-overridable `TargetNetID`
  (zero-value = all-zero NetID heuristic for initial
  probes). Probe builds finding note "TwinCAT <name>
  <major>.<minor>.<build>" (e.g. "TwinCAT TCatRouter
  3.1.4024"). Six-factor scoring: protocol_risk 80,
  exposure 70, auth_state 85, capability 30/70,
  impact_class 75, cve_exposure 10. ProxyHandler is
  fail-closed.

### Tests

`+8 tests` (wire frame layout pinned, version round-
trip, NUL-padded name trim, short frame, bad AMS/TCP
prefix, request flag set, ADS error code, length
overflow).

### Build

Plugin count 28 → 29. Build sizes unchanged (default
23.0 MB, offensive 23.7 MB, mini 21.3 MB). INSTALL.md
unchanged (twincat is read-only fingerprint, no flags
or runtime config exposed at install-doc level).

## [1.53.0] — 2026-05-05

### Added

- **enip per-(class, instance, attribute) gating** for
  SendRRData / SendUnitData. Closes the v1.32+ B
  carryover. Operators can now restrict CIP MR requests
  to specific (class, instance, attribute) triples; an
  allowlisted SendRRData can no longer be used to
  write to ANY object. Three match strictnesses:
  MatchExact (all three must match), MatchClassInstance
  (Attribute wildcarded), MatchClassOnly (Instance +
  Attribute wildcarded).
- `internal/protocols/enip/wire/epath.go` (new): CIP
  MR EPATH parser. Supports 8/16/32-bit logical-segment
  forms for class/instance/attribute. Refuses unknown
  segment types (port-segment, symbolic, network).
- AllowlistHash gains attrs dimension with separator
  `0xF2`. Empty attrs list yields v1.27 hash for
  backward-compat.

### Changed

- `enip.SessionMutation(target, allowed)` is now
  `enip.SessionMutation(target, allowed, attrs)`.
  `SessionMutationLegacy(target, allowed)` preserved.
- `WriteGatedHandler.shouldForward` refactored:
  `cmdAllowed` + `attributeAllowed` helpers.

### Tests

`+12 tests` (6 wire + 6 gate).

### Build

3-variant matrix unchanged. INSTALL.md unchanged.

## [1.52.0] — 2026-05-05

### Added

- **s7 per-(area, db, byte-address) gating for
  FuncWriteVar (0x05)**. Closes the v1.32+ A
  carryover. Operators can now restrict WriteVar to
  specific (area, db, byte-range) tuples; an
  allowlisted WriteVar can no longer be weaponised to
  mutate any address. Wire parser
  (`internal/protocols/s7/wire/items.go`) extracts
  per-item Area / DB / ByteAddr / Length from the
  S7ANY parameter-area items. Gate
  (`offensive/write/s7/`) gains `AllowedWriteItem`
  with byte-range Matches semantics; empty list
  preserves v1.27 FC-only gating.
- **AllowlistHash gains a per-item dimension** with
  hash separator `0xF1`. Empty items list yields the
  same hash as v1.27 — pre-v1.52 confirm-tokens keep
  validating. Operators who configure per-item
  allowlists must re-mint.

### Changed

- `s7.SessionMutation(target, allowed)` is now
  `s7.SessionMutation(target, allowed, items)`.
  `SessionMutationLegacy(target, allowed)` preserved
  for any 2-arg caller (none in-tree).

### Tests

`+11 tests` (7 wire + 4 gate).

### Honest scope

Bit-level addressing (DB42:100.3) intentionally NOT
supported. CLI flag plumbing (`proxy listen --write-
item …`) is a future cycle — wire + gate primitives
land in this chunk.

### Build

3-variant matrix unchanged. INSTALL.md unchanged.

## [1.51.0] — 2026-05-05

### Added

- **MMS ACSE A-ASSOCIATE-REQUEST for IEC 61850-8-1 IED
  fingerprinting**. Closes the long-standing v1.32+ E
  carryover. Bumps MMS plugin confidence from ~0.8
  (COTP-level disambig only) to ~0.95 (IED handshake
  confirmed).
  - `BuildACSEAssociateRequestMMS()` — hand-coded
    static OSI Session CONNECT + Presentation CP +
    ACSE AARQ blob (~120 bytes) requesting the
    `1.0.9506.2.3` application context. Reverse-
    engineered from libiec61850; verified against
    Conpot.
  - `ParseACSEAssociateResponseMMS(buf)` — byte-
    pattern scan for the OID in the AARE response.
    Layout-agnostic, zero-allocation; robust to vendor
    variation in AARE structure.
  - Plugin.Probe sends the AARQ after a positive
    COTP-CC; on OID match the finding note becomes
    "MMS ACSE associated (IEC 61850-8-1)". Falls back
    to the v1.25 COTP-CC note on any failure so non-
    IEC-61850 MMS-style servers see no behaviour change.

### Tests

`+6 tests` (acse_test.go):
MMSApplicationContextOIDBytes, BuildACSEAssociateRequestMMS,
Parse_Positive, Parse_NoOID, Parse_TooShort,
Parse_OIDAtBoundary, Parse_PartialOID.

### Honest scope

The AARQ is static (not target-customised) and the AARE
parse is OID-pattern scan (not full BER). Lab validation
against real Mark VIe / SEL / GE Multilin / ABB IEDs is
still pending (same gap as the v1.28 ProConOS + GE-SRTP
plugins).

### Build

3-variant matrix unchanged.

INSTALL.md unchanged — fingerprint confidence is a
plugin-internal concern not visible at install-doc
level.

## [1.50.0] — 2026-05-05

### Added

- **macOS `sandbox_init(3)` integration** (cgo-gated,
  opt-in). Closes the long-standing carryover from v1.32+.
  Adds an opt-in cgo wrapper at
  `offensive/sandbox/sandbox_darwin_cgo.go` that applies
  per-Profile `.sb` Scheme strings via `sandbox_init(3)`.
  Three profiles:
  - **exploit**: full network, deny process-exec, file
    writes restricted to /tmp + /private/var/folders.
  - **harvest**: network-outbound only, deny process-exec,
    file writes to /tmp only.
  - **dial**: deny network*, allow file-write under
    /dev/tty + /dev/ptmx (UART config), deny process-exec.
- **`make build-offensive-darwin-sandboxed`** target.
  Sets `CGO_ENABLED=1` to light up the sandbox wrapper.
  Emits `bin/elsereno-offensive-sandboxed` at ~23.2 MB.
  NOT in release tarballs; operators who want it run
  the make target locally.

### Changed

- **Default release builds keep `CGO_ENABLED=0`** —
  static-Linux invariant unchanged, default macOS
  binary still pure-Go with the existing "sandbox:
  unavailable on darwin" degradation.
- Pre-existing `TestLoad_ValidProfileOnNonLinux` skips
  on darwin+cgo via a new `hasMacOSSandboxInit()`
  probe.

### Tests

`+3 darwin-cgo tests`: DarwinProfileSchemesPresent,
DarwinLoadInvalidProfile, DarwinAllProfilesHaveDistinctSchemes.

### Build

| Variant                      | v1.49     | v1.50     |
|------------------------------|-----------|-----------|
| default                      | 23.0 MB   | 23.0 MB   |
| offensive                    | 23.7 MB   | 23.7 MB   |
| mini                         | 21.3 MB   | 21.3 MB   |
| offensive-darwin-sandboxed   | n/a       | 23.2 MB   |

INSTALL.md updated with the 2-mode macOS sandbox table
and the per-profile Scheme rationale (per the v1.49
standing directive — every cycle updates docs when
behaviour changes).

## [1.49.0] — 2026-05-05

### Added

- **Linux distribution packaging** — deb / rpm / apk via
  goreleaser nfpm. 18 packages per release (3 variants ×
  3 formats × 2 archs). Binary is statically linked
  (verified `file → "ELF … statically linked, stripped"`,
  `go tool nm` shows no libc symbols) so it runs on any
  Linux distribution with kernel ≥ 2.6.32.
  - `elsereno`           — default (read-only) build with
                            systemd units shipped.
  - `elsereno-offensive` — offensive build, coexists with
                            default at /usr/bin/elsereno-offensive.
  - `elsereno-mini`      — device deployment, no systemd
                            unit (mini's serve is a stub).
- **Hardened systemd units** for `serve` and `audit serve`
  daemons. NoNewPrivileges, ProtectSystem=strict,
  MemoryDenyWriteExecute, RestrictNamespaces, empty
  CapabilityBoundingSet, SystemCallFilter narrowed to
  @system-service minus mount/swap/reboot/debug/cpu-emul.
  Ship disabled — operator explicitly enables.
- **Pre/post-install scripts** that create the elsereno
  system user/group, apply the tmpfiles drop-in, and
  print an operator quick-start MOTD. Persistent state
  (`/var/lib/elsereno`, `/var/log/elsereno`, `/etc/elsereno`)
  survives `apt remove`; only `apt purge` wipes it.
- **`INSTALL.md`** (new top-level doc, ~250 lines).
  Comprehensive install + upgrade + uninstall doc with
  per-platform feature matrix, Linux vs macOS pros/cons,
  troubleshooting table, build-from-source flow.

### Process

Per operator instruction, every cycle from here forward
will update both macOS + Linux artefacts and modify
documentation (INSTALL.md and any platform-specific
docs) to reflect changes — no more silent platform
drift.

### Tests

No new code tests this cycle (packaging-only). Full
goreleaser snapshot produces all 18 packages; sample
deb verified to contain the binary + systemd units +
config sample + manpage.

### Build

3 binaries × 2 archs × (1 tarball + 1 deb + 1 rpm +
1 apk) = 24 artefacts per arch + checksums.txt + SBOMs
+ cosign sigs in every release.

  default      23.0 MB binary, ~8.5 MB deb (gz)
  offensive    23.7 MB binary, ~8.7 MB deb
  mini         21.3 MB binary, ~7.8 MB deb

## [1.48.0] — 2026-05-05

### Added

- **`elsereno proxy replay --stats`** — summary mode:
  per-direction chunk count + total bytes + time range
  of the matching subset. No per-chunk lines. Composes
  with --dir / --since / --until. Mutually exclusive
  with --limit / --tail / --json (each error message
  names the specific pair).

### Changed

- All mutex-flag checks for `proxy replay` consolidated
  into `validateMutexFlags`. Pre-existing
  --limit/--tail check moved there too.

### Tests

`+3 tests`: StatsSummary, StatsEmpty, StatsMutexFlags.

### Build

3-variant matrix unchanged.

## [1.47.0] — 2026-05-05

### Added

- **`elsereno proxy replay --tail N`** — symmetric
  counterpart to v1.46's `--limit`. Emits the LAST N
  matching chunks. Ring-buffered so memory caps at N
  entries regardless of capture size — multi-GB session
  tail-N doesn't balloon RAM.

### Changed

- `runProxyReplay` splits into `runProxyReplayStream`
  (default + --limit; emit-as-you-walk) and
  `runProxyReplayTail` (--tail; ring-buffered). New
  `emitChunk` helper unifies per-chunk rendering across
  both paths.
- `--limit` + `--tail` rejected at parse time as mutually
  exclusive (operator-confusion guard).

### Tests

`+3 tests`: TailEmitsLastN, TailLargerThanCapture,
TailWithLimitRejected.

### Build

3-variant matrix unchanged.

## [1.46.0] — 2026-05-05

### Added

- **`elsereno proxy replay --limit N`** — caps output at
  N matching chunks. Applied AFTER --dir / --since /
  --until filters so "first 10 c→u writes in window"
  gets exactly 10. Default 0 preserves pre-v1.46
  unbounded streaming. The cap fires inside the file
  walker (errReplayLimitReached sentinel) so multi-GB
  captures don't keep being read.

### Changed

- `runProxyReplay` extracted `chunkPassesFilters` helper
  encapsulating DirHeader skip + dir filter +
  timeWindow.contains. Brings cyclomatic complexity back
  under the linter ceiling as flag composition grows.

### Tests

`+3 tests`: LimitTruncates, LimitZeroIsNoCap,
LimitAfterFilters.

### Build

3-variant matrix unchanged.

## [1.45.0] — 2026-05-05

### Added

- **`elsereno proxy replay --json`** — machine-readable
  output for jq / downstream tooling. Each ChunkEvent
  emits as one JSON object per line; header preamble
  suppressed so stdout stays a clean NDJSON stream.
  Composes with --dir / --since / --until filters
  (v1.44+); --json controls presentation only.

### Fixed

- **`proxy replay` skipped a phantom `c→u  0B` line** in
  legacy (non-JSON) output. `replay.Replay` calls the
  callback once per record including the `DirHeader`
  metadata event; the dispatcher used to let it fall
  through to formatChunk where the arrow defaulted to
  "c→u" because the only `Dir==…` check was for
  `DirUpstreamToClient`. The dispatcher now skips
  DirHeader explicitly. SeekHeader already surfaces the
  metadata via the preamble; the chunk stream is now
  chunk-only.

### Tests

`+2 tests` (JSONOutput, JSONOutput_RespectsFilters); 1
existing test (RendersHeaderAndChunks) updated to assert
on the actual chunk arrow rather than the phantom one.

### Build

3-variant matrix unchanged.

## [1.44.0] — 2026-05-05

### Added

- **`elsereno proxy replay --since RFC3339 --until RFC3339`**
  — forensic time-window narrowing for long captures. Both
  bounds optional and inclusive. Either side missing means
  "no bound on that side". Microsecond precision (RFC3339Nano)
  matches the recorder's wire format. Either-or invalid
  format and `since > until` raise EX_USAGE with friendly
  hints. `# window` header line announces the active bounds
  so the operator sees what was applied.

### Tests

`+4 tests`: TimeWindow_ParseValid, TimeWindow_Contains,
TimeWindow_FiltersOutput, BadSinceUsageError.

### Build

3-variant matrix unchanged.

## [1.43.0] — 2026-05-05

### Added

- **`tui --rate N`** — slow-motion playback for demos.
  Plumbs the long-existing `feeds.Replay.Rate` /
  `feeds.Stdin.Rate` field through a CLI flag. Useful
  when a long capture should pace itself at N events/sec
  for an audience instead of streaming all events
  instantly. Default 0 preserves pre-v1.43 unbounded
  behaviour. Ignored for `--watch` / `--input` / no-flag
  interactive modes (those are live).

### Tests

`+3 tests`: ReplayPropagatesRate, StdinPropagatesRate,
RateZeroIsUnlimited.

### Build

3-variant matrix unchanged.

## [1.42.0] — 2026-05-04

### Added

- **`tui --replay` reads `elsereno-tui-record/v1`** —
  closes the loop with v1.41-chunk-1's `--record`. The
  replayer's parseRecord dispatcher now handles BOTH the
  legacy `ndjson:v1` (scan-output) schema AND the new
  v1.41 schema. End-to-end workflow:
    1. `tui --replay scan.ndjson --record session.ndjson`
       captures the live session.
    2. `tui --replay session.ndjson` plays it back.
  Per-type dispatch: `finding` → FindingMsg, `audit` →
  AuditMsg, `scan_progress` → ScanProgressMsg, `feed_closed`
  → FeedClosedMsg, unknown → AuditMsg with hint
  (forward-compat).

### Changed

- `internal/tui/feeds/ndjson_stream.go` parseRecord
  restructured into a 2-step decode (schemaPeek →
  schema-specific). parseScanFinding extracted from
  legacy path; parseTUIRecord new. Unknown-schema
  fallback now lists supported schemas in the friendly
  AuditMsg.

### Tests

`+8 tests` (internal/tui/feeds/tuirecord_test.go):
- ParseTUIRecord_FindingType / AuditType /
  ScanProgressType / ScanProgressNilFields /
  FeedClosedType / FeedClosedNilErr / UnknownType /
  MultiSchemaInOneFile.

### Build

3-variant matrix unchanged.

## [1.41.0] — 2026-05-04

### Added

- **`elsereno tui --record FILE.ndjson`** — symmetric
  counterpart to v1.29-chunk-3's `--replay`. Tees every
  event the TUI's model receives onto a file as the
  session runs. New `elsereno-tui-record/v1` schema with
  type-tagged events covering finding / audit /
  scan_progress / feed_closed. Useful for screen-recording,
  training, forensics, or attaching exact event streams to
  bug reports. File created 0600. Recording is best-effort:
  encode errors are silenced so the TUI doesn't die for an
  unwritable file.

### Changed

- `tui.Run(ctx, mode, feed, out, in)` is preserved as a
  back-compat shim. The new entry point is
  `tui.RunWithOpts(... opts RunOpts)` with `RunOpts.Record
  io.WriteCloser`. Existing callers (incl. teatest tests)
  keep working.
- The feed goroutine's `FeedClosedMsg` now flows through
  the emit shim (not directly through `prog.Send`) so the
  close event lands in the record file. Without this the
  operator's record would always end one event short.

### Tests

`+8 tests` (internal/tui/recorder_test.go):
- Tee_FindingMsg, Tee_AuditMsg, Tee_ScanProgressMsg,
  Tee_FeedClosedMsg, Tee_UnknownMsgPassthrough, Stats,
  NDJSONLineFormat, Close_idempotent.

### Build

3-variant matrix unchanged. Mini variant unaffected
(`//go:build !mini` keeps the recorder out of the device
build).

## [1.40.0] — 2026-05-04

### Added

- **`elsereno plugins ports`** — port → plugins reverse
  index. Default output is plain-text "port  [plugin1
  plugin2 ...]" sorted by port; `--json` emits the map for
  jq pipelines. Same-port collisions (mms + s7 both on
  port 102) list every claimer alphabetically. Useful
  when operators see a port hit in a discovery sweep + want
  to know which `--plugin` value to pass to `scan` /
  `fingerprint validate`. Plugins with DefaultPort=0
  (atmodem, banner) are skipped.

### Tests

`+4 tests` (cmd/elsereno/cmd_plugins_test.go):
- BuildPluginsByPort_ColocatedPort, _SkipsZeroPort,
  PluginsPortsCmd_TextOutput, _JSONOutput.

### Build

3-variant matrix unchanged.

## [1.39.0] — 2026-05-04

### Added

- **`elsereno discover --hosts <file>`** — natural
  counterpart to v1.15-chunk-2's `--auto <CIDR>`. Operators
  with curated host inventories (CMDB / asset-management
  export, nmap host-list extract, hand-maintained list)
  no longer need to expand sparse CIDRs. The flag accepts
  one IP per line; `#` for full-line and inline comments;
  blanks skipped; tolerates `host:port` lines (port half
  stripped, IPv6 `::` skip-heuristic preserves their full
  form); --max-hosts caps the walk; line-numbered error
  context on bad IP. Mutex with --auto.

### Tests

`+7 tests` (cmd/elsereno/cmd_discover_test.go):
- HappyPath, HostPortStrip, IPv6Preserved, MaxHostsCap,
  EmptyFile, BadIP, MissingFile.

### Build

3-variant matrix unchanged.

## [1.38.0] — 2026-05-04

### Added

- **`elsereno fingerprint capture` sub-verb** — natural
  companion to v1.37's `validate --file`. Opens a localhost
  TCP listener, accepts ONE connection, drains the client's
  bytes via `io.ReadAll`, writes them 0600 to `--output`.
  Operators with lab access run `capture` in one window,
  point their PLC tool at the port, then `validate --file`
  the resulting capture in a follow-up command. Refuses to
  write 0-byte files (defensive against silent-junk
  captures). Uses a context-aware Accept wrapper —
  `net.Listener.Accept` isn't ctx-aware, we close the
  listener on cancel to force the goroutine to return and
  translate the "closed network connection" error to
  ctx.Err().

### Tests

`+4 tests` (cmd/elsereno/cmd_fingerprint_test.go):
- HappyPath: end-to-end fixed-port + in-process dial +
  byte roundtrip + 0600 perms check
- MissingOutput: required-flag rejection
- TimeoutOnIdleListener: ctx deadline fires + no junk file
- ClientClosesEmpty: empty client write → error

Plus 2 test helpers: `waitForListenPort` (regex-based stdout
poll) and `dialTimeout` (context-aware Dial wrapper).

### Build

3-variant matrix unchanged.

## [1.37.0] — 2026-05-04

### Added

- **`elsereno fingerprint validate` CLI verb** — captured-
  bytes harness for any registered plugin's Probe. Closes
  the v1.28 chunks 1+2 carryover that flagged the ProConOS
  + GE-SRTP fingerprints as "confidence ~0.7 pending
  real-PLC validation". Operators with lab access (Berghof
  / Lenze / Phoenix Contact ILC for ProConOS; GE Mark VIe
  / RX3i / PACSystems for GE-SRTP, plus any other plugin)
  can now feed captured response bytes via `--file` or
  `--hex` and inspect the resulting Finding (factors,
  score, severity) in either human-readable text or JSON.
  Useful for: validating a fingerprint against your own
  hardware, regression-pinning a vendor's response, or
  forensics on an unexpected probe result.

  Mechanism: spins up a `lc.Listen(ctx, "tcp", "127.0.0.1:0")`
  responder that drains the probe's request bytes + writes
  the operator-supplied reply once + closes. Drives
  `plugin.Probe` through the listener; emits the result.
  No DB, no scope, no scan-orchestration — just the parser
  path.

### Tests

`+13 tests` (cmd/elsereno/cmd_fingerprint_test.go):
- Hex / file input, whitespace-stripped paste, empty / bad
  hex, missing / unknown / mutex flags, missing file,
  nil-Finding emit, silent-responder default, ctx-cancel
  fallback, table-driven across proconos + gesrtp.

### Build

3-variant matrix unchanged.

## [1.36.0] — 2026-05-04

### Added

- **`GET /api/v1/inputs/preview` endpoint** — dashboard
  parity with the `scan` / `tui --input` CLI verbs.
  Accepts `?kind=list:<path>|nmap:<path>|stdin` +
  optional `default_port`. Returns
  `{count, targets[], truncated}` with the targets sample
  capped at 200 entries. Read-only — does NOT run a scan;
  just verifies that the input file parses cleanly. Closes
  the v1.31 carryover ("Dashboard `--input` parity with
  scan + tui").
- **`internal/inputs/preview` package** — dependency-light
  dispatcher backing the new endpoint. Handles list:/
  nmap:/stdin kinds; provider kinds (shodan / censys /
  fofa / zoomeye / onyphe / internetdb) return a typed
  `ErrUnsupportedKind` so callers surface a friendly
  "preview supports list/nmap/stdin only" error.

### Changed

- `internal/web/handlers/api.go` wires
  `GET /api/v1/inputs/preview` into the APIV1 sub-router.
- `internal/web/openapi/spec.go` registers the new path so
  `GET /api/v1/openapi.yaml` documents it. `docs/openapi.yaml`
  regenerated via `elsereno api openapi`.

### Tests

`+14 tests` (8 dispatcher + 6 handler):
- `internal/inputs/preview/preview_test.go`: stdin happy,
  list happy, nmap minimal-XML happy, list missing,
  nmap missing, unsupported-kind table for 6 provider
  prefixes + bogus + empty, stdin nil-guard,
  `ErrUnsupportedKind` error rendering.
- `internal/web/handlers/inputs_test.go`: list happy
  (200 + schema + count + sample), missing-kind 400,
  bad default_port 400, unsupported-kind table-driven 400,
  missing-file 404, 250-target truncation cap at 200.

### Build

3-variant matrix unchanged.

## [1.35.0] — 2026-05-04

### Added

- **`elsereno proxy listen --plugin pcworx|mms|enip|s7`**.
  The 4 legacy-ICS plugins gained Recorder fields in earlier
  cycles (pcworx + mms in v1.28 chunk 3 as session-level
  POC; enip + s7 in v1.30 chunk 1 as wire-aware) but had no
  CLI verb. v1.35 wires them as new `--plugin` values, so
  `proxy listen --record FILE --plugin enip ...` (etc.)
  works the same as for the original 7 plugins.
  - `--intent <description>` (repeatable): pcworx + mms
    session-level free-text tags rolled into the session
    mutation hash.
  - `--cip-command <uint16>` (repeatable): enip CIP
    encapsulation command allowlist (e.g. 0x70 SendUnitData).
  - `--s7-fc <uint8>` (repeatable): s7 function-code
    allowlist (e.g. 0x05 WriteVar). Range-checked against
    the 8-bit cap.

### Tests

- `cmd_proxy_attachrecorder_offensive_test.go` (NEW, 13
  cases). Pins every gated-proxy handler type that ships a
  Recorder field is covered by `attachRecorder`. A new
  plugin that ships a Recorder field but doesn't get added
  to the type-switch will fail this test —
  mechanical enforcement of the "Recorder field implies
  attachRecorder arm" invariant.

### Build

3-variant matrix unchanged.

## [1.34.0] — 2026-05-03

### Changed

- **Tree-wide `//nolint:gosec` → `// #nosec G<NNN>`
  migration** (76 markers across 49 files). Completes
  the b611f5c (pre-v1.28) convention enforcement. v1.32
  chunk 1 covered cmd/elsereno/ (10 markers); v1.34 chunk 1
  covers the remainder in internal/**, offensive/**.
  Method: 58 markers with explicit G-codes bulk-swapped via
  regex (preserving rationale text); 18 G115 by content
  bulk-swapped; 1 composite G306+G703 fixed to gosec's
  multi-code syntax. Standalone gosec binary in CI's `sec`
  job only honours same-line `// #nosec` form; this fully
  enforces PITF-030 tree-wide.

### Fixed

- **`offensive/write/enip/write.go`** had a pre-existing
  comment-eats-statement bug at line 148: a `//nolint:gosec`
  directive was on the same physical line as a tabbed
  `buf = append(buf, body...)` statement. Go's `//` line
  comment swallowed the append, silently dropping the
  SendRRData body. Tests passed because they only checked
  for the service byte (which lived in `buf` already from
  `MarshalHeader`). The migration sweep surfaced this when
  the directive swap broke the assembly. Fix: split into
  two lines and restored the `append` call.

### Tests

No new tests this cycle (text-only directive change). All
existing tests pass under `-race`; lint clean; `make sec`
ok.

### Build

Unchanged (text-only changes).

## [1.33.0] — 2026-05-03

### Added

- **teatest program-level integration tests for the TUI
  runner.** Closes the v1.30 + v1.31 carryover. New
  `internal/tui/program_test.go` (10 cases) drives the
  bubbletea program through `teatest`, sends keypresses +
  tea.Msg events, asserts on rendered output + final model
  state. Cases pin: quit-on-q / ctrl+c, header+4-pane
  rendering on first paint, FindingMsg → protocol-in-output,
  AuditMsg → line-in-audit-pane, full filter-edit cycle
  (`/scan` + Enter), Tab focus cycle, severity-band rendering
  (score 95 → "critical"), terminal-too-small fallback, and
  a full-session clean-output drain (no panic / runtime /
  goroutine traces leaking).

### Changed

- **Indirect deps** from teatest:
  + `github.com/charmbracelet/x/exp/teatest` (test-only)
  + `github.com/charmbracelet/x/exp/golden`  (indirect,
    teatest's diff renderer)
  + `github.com/aymanbagabas/go-udiff` v0.2 → v0.3 (indirect,
    used by teatest's golden helper)
  + `github.com/charmbracelet/colorprofile` v0.2.3-pre →
    v0.3.2 (teatest required ≥ 0.3; lipgloss already used
    colorprofile, so this is a minor bump on a pre-existing
    linked path).

### Tests

`+10 program-level integration tests` this cycle. All pass
under `-race`. Pre-existing 53 component tests + 30 feed
tests unchanged — no regressions.

### Build

| Variant   | v1.32   | v1.33   | Δ      |
|-----------|---------|---------|--------|
| default   | 22.9 MB | 23.0 MB | +0.1   |
| offensive | 23.6 MB | 23.7 MB | +0.1   |
| mini      | 21.3 MB | 21.3 MB | 0      |

Mini variant unchanged — `internal/tui/` carries `//go:build
!mini`. The +0.1 MB on default + offensive comes from the
`colorprofile` minor bump (transitive teatest requirement);
lipgloss already linked colorprofile, so this is a version
bump on a pre-existing path, not a new linked dependency.

## [1.32.0] — 2026-05-03

### Changed

- **gosec marker hygiene** (cmd/elsereno/). Completes the
  b611f5c migration for the cmd/elsereno/ subtree. 10
  `//nolint:gosec` directives swapped to `// #nosec G<NNN>`
  native form. PITF-030 rationale: golangci-lint's bundled
  gosec accepts both forms, but the standalone gosec binary
  in CI's `sec` job only honours the same-line `// #nosec`
  form. Each line preserves its original rationale; only
  the directive shape changes. The composite case
  (cmd_doctor.go) drops the gosec half from a `//nolint:
  gosec,unconvert` line that already had `// #nosec G115`
  same-line, keeping `//nolint:unconvert` standalone.

### Notes

- Wider tree (~65 more markers across
  internal/protocols/**, offensive/write/**, internal/audit/**,
  offensive/sandbox/**) intentionally untouched. Those have
  coexisted with the convention since b611f5c and `make sec`
  has been exit 0 throughout. A v1.33+ sweep can finish the
  parity if/when the operator wants it.

### Tests

No new tests this cycle (text-only change). Existing tests
pass under -race; lint clean; `make sec` ok.

### Build

3-variant matrix unchanged.

## [1.31.0] — 2026-05-03

### Added

- **TUI `--input` parity with batch `scan`**. Closes the
  v1.30-chunk-3 carryover. v1.30 wired only `--input
  list:FILE` and explicitly deferred the 7 other kinds; v1.31
  brings nmap:, stdin, shodan:, censys:, fofa:, zoomeye:,
  onyphe:, internetdb: to first-class operands on
  `elsereno tui --input KIND`. The input-parsing dispatcher
  was extracted to a shared helper (`cmd_input_parse.go`)
  that both `scan` and `tui` call, so future input kinds
  land in one place rather than diverging across two
  switches.
- **`--api-creds-file` flag on `elsereno tui`**. Same shape
  as `elsereno scan --api-creds-file`. Required for the 5
  API-keyed providers (shodan, censys, fofa, zoomeye,
  onyphe); ignored for the rest.

### Changed

- `cmd/elsereno/cmd_scan.go`'s `readTargets` is now a 5-line
  shim over the new `parseInput` dispatcher in
  `cmd_input_parse.go`. Behaviour is unchanged; the refactor
  drops 3 imports + 50 lines from cmd_scan.go.
- `cmd/elsereno/cmd_tui.go`'s `newTUICmd` was refactored to
  use a `registerTUIFlags()` helper. The flag-count growth
  pushed `newTUICmd` past the `funlen` ceiling; extracting
  flag registration brings it back under.
- `pickFeedArgs` (private struct on cmd_tui.go) gains
  `apiCredsFile` field.

### Tests

- `cmd/elsereno/cmd_input_parse_test.go`: 7 cases — stdin
  injected reader, list:FILE happy path, list missing file,
  nmap missing file, nmap minimal-XML happy path, unknown
  kind, stdin defaults to os.Stdin guard.

**+7 tests this cycle.** All pass under `-race`; lint clean
across all 3 build variants.

### Build

3-variant matrix unchanged (default 22.9 MB / offensive
23.6 MB / mini 21.3 MB stripped). The change is pure
refactoring + flag addition; no new code paths in offensive,
no new bytes in mini.

## [1.30.0] — 2026-05-02

### Added

- **Record-replay wire-up into 9 wire-aware gates**. Closes the
  v1.28 chunk-3 deferral. Extends the optional
  `Recorder *replay.Recorder` field from the two session-level
  POC gates (pcworx, mms) to all 9 wire-aware gates that parse
  the `io.ReadWriter` internally: sip, iax2, pbxhttp, modbus,
  opcua, bacnet, cwmp (the 7 explicitly listed in the v1.28
  commit message) plus enip and s7 (also wire-aware, missed
  by the original count). Wrapping happens AFTER the auth
  check + BEFORE any reader is constructed (`bufio.NewReader`,
  `wire.ReadFrame`, `http.ReadRequest`, etc.), so allowlist
  routing decisions read from the wrapped reader and the
  recording captures every byte the client sent — including
  refused frames + pre-parse junk, useful for forensic
  post-mortems where "what did the attacker actually send?"
  matters more than "what was forwarded".
- **`--record FILE` flag on `proxy listen`**. Operator-facing
  half of the wire-up. Opens `replay.Recorder` BEFORE
  `Authorise()` so a permission failure on the capture file
  fails fast (no audit row for an unstartable session).
  Threads the recorder onto the concrete handler via
  `attachRecorder()` type-switch. File is created 0600 with
  schema `elsereno-replay/v1`. Prints `proxy: recording to
  <path>` on listener bind. Closed on every exit path.
- **`elsereno proxy replay FILE` sub-verb**. Renders an
  `elsereno-replay/v1` capture as human-readable lines:
  `[HH:MM:SS.uuuuuu] c→u  NNB  hex-preview…`. Header preamble
  shows protocol + target + start-time. `--dir
  client|upstream|both` filter (default both; aliases `c`/`u`
  accepted). `--hex-limit N` truncates the per-chunk hex
  preview at N bytes (default 32; 0 = full).
- **TUI scan launcher (`feeds.Interactive`)**. Closes the
  v1.29 chunk-2 deferral (interactive mode previously used
  `feeds.Empty` placeholder). Runs `scanner.Scanner` from
  inside the TUI; emits FindingMsg per finding +
  ScanProgressMsg per advance + AuditMsg per scanner error
  (warn-and-continue, mirroring batch `scan`). Initial 0/N
  progress so the bar renders immediately rather than "idle";
  final `ScanProgressMsg{Total: 0}` on close. New
  `--input list:FILE` + `--default-port` flags on
  `elsereno tui`.
- **TUI audit-pane substring filter**. `/` enters edit mode
  (only when the audit pane is focused), type substring,
  Enter commits to `AuditFilter`, Esc cancels (preserves
  previous filter). Esc outside edit mode clears any active
  filter. Backspace pops one rune from the draft. Match is
  case-insensitive `strings.Contains`. Pane header shows
  live draft while editing + active filter when committed +
  empty-state distinguishes "no events yet" from "no events
  match /<filter>".

### Changed

- `pickFeed` in `cmd/elsereno/cmd_tui.go` now takes a
  `pickFeedArgs` struct rather than 6 positional arguments —
  the `--input` + `--default-port` additions pushed the count
  past the linter's argument-count ceiling.
- `feeds.Replay`'s NDJSON streaming logic was refactored into
  `streamNDJSON` in `feeds/ndjson_stream.go` (already in v1.29
  chunk 4); v1.30 reuses the helper for `feeds.Stdin` and
  doesn't change the protocol.

### Tests

- `offensive/write/modbus/gatedproxy_test.go`:
  `TestHandle_RecordsBytesWhenRecorderSet` (canonical
  wire-aware shape; the 8 other gates share the wrap point).
- `cmd/elsereno/cmd_proxy_replay_offensive_test.go`: 4
  cases (header roundtrip, --dir parser, arrows, hex truncation).
- `internal/tui/feeds/interactive_test.go`: 5 cases
  (happy path, empty targets, probe error, ctx cancel, name).
- `internal/tui/filter_test.go`: 9 cases (filter logic +
  edit-mode key handling).

**+19 tests this cycle.** All pass under `-race`; lint clean
across all 3 build variants.

### Build

3-variant matrix unchanged from v1.29:
default 22.9 MB / offensive 23.6 MB / mini 21.3 MB
(stripped `-s -w`). Mini variant continues to exclude
`internal/tui/` via `//go:build !mini`, so the new
`Interactive` feed + filter logic doesn't grow the device
build. The `proxy listen --record` and `proxy replay` paths
are `//go:build offensive` and absent from default + mini.

## [1.29.0] — 2026-05-01

### Added

- **Interactive terminal UI (`elsereno tui`)** — full
  bubbletea Model/View/Update with 4-pane layout (findings
  table / triage chips / audit feed / scan progress). Four
  modes: interactive (default; chunk 2 ships empty feed —
  the live-scan path lands in v1.30), `--replay FILE`
  NDJSON capture playback, `--feed -` stdin pipe, `--watch
  URL --bearer TOKEN` remote SSE consumer. Tab cycles focus,
  j/k/g/G navigate findings, q/ctrl+c quits.
- **Mini build variant (`-tags mini`)**. 3-variant goreleaser
  matrix: default + offensive + mini. Mini excludes the
  dashboard (`serve`, `api`) + the TUI verb to keep the
  binary small for device deployments (jump hosts, embedded
  rigs). Stub verbs print descriptive errors + exit
  EX_UNAVAILABLE (69) instead of cobra's "unknown command".
  Stripped binary sizes: default ~23 MB / offensive ~24 MB /
  mini ~21 MB. CI gates `build-mini` to catch tag bitrot.

### Fixed

- `cliError`-wrapped errors are now printed to stderr before
  exit. Cobra's `SilenceErrors: true` was masking them, so
  most call sites of `fail()` exited silently with a typed
  exit code. Conservative fix: print only when
  `cliError.Error()` returns non-empty (preserves
  silent-exit for commands that print before returning).

## [1.28.0] — 2026-04-30

### Added

- **`proconos` fingerprint plugin** (TCP/20547, best-effort).
  KW-Software ProConOS runtime kernel that ships under multiple
  PLC brands (Phoenix Contact ILC + Berghof + IPC2u + ABB / B&R
  / Lenze re-skins). 16-byte canonical hello (variant matching
  Wireshark dissector + metasploit auxiliary scanner).
  Permissive banner classifier accepts both the v2 hello echo
  and the older `0xCA 0xFE 0x00 0x00 0xCE 0xFA 0xDE 0xC0`
  alt-prefix form found in Berghof + Lenze captures. **Honest
  scope**: confidence ≈ 0.7 (vs ≈ 0.95 for v1.20-v1.25 plugins);
  needs real-PLC validation. Plugin count: 27 → 28.
- **GE-SRTP service-0x21 (Read PLC Long Status) follow-up**.
  v1.21 chunk 4 shipped the connection-init probe + model-hint
  extractor; v1.28 adds an opt-in second exchange that asks
  the PLC for its long status. Wire layer gains
  `ServiceLongStatus`, `BuildReadLongStatus`, `LongStatusInfo`,
  `ParseLongStatus`. Probe now produces "SRTP model=PACSystems
  fw=V12.45.7" finding notes when both probes succeed; falls
  back to the v1.21 result on follow-up failure (no
  regression). **Honest scope**: needs real Mark VIe / RX3i /
  PACSystems validation.
- **Record-replay wire-up into pcworx + mms gates (POC)**.
  Optional `Recorder *replay.Recorder` field on
  `WriteGatedHandler`. When non-nil, Handle() wraps both
  client + upstream io.ReadWriter pairs through the recorder
  before the io.Copy goroutines start. Bytes flow through
  transparently while being timestamped + direction-tagged
  + persisted to NDJSON. Defaults to nil (no behavioural
  change for existing operators). Wire-aware gates (sip /
  iax2 / pbxhttp / modbus / opcua / bacnet / cwmp) wire-up
  + CLI integration is v1.29+.

### Notes

- 26 new tests across the 3 chunks.
- cve_exposure non-zero plugin count: 24/27 → 25/28 (proconos
  ships with cve_exposure=7).
- Both new fingerprints (proconos + GE-SRTP service-0x21)
  carry explicit "needs validation" callouts in package
  docstrings + plugin Description.

### Deferred to v1.29+

- Wire record-replay into the 7 wire-aware gates (sip / iax2
  / pbxhttp / modbus / opcua / bacnet / cwmp).
- CLI integration: `elsereno proxy listen --record FILE` flag.
- Offensive plugin trios for v1.20+v1.21 fingerprints (FINS /
  SLMP / SRTP / KNX / M-Bus / DLMS write services) — blocked
  on real-PLC test vectors.
- MMS ACSE association layer (full ASN.1 BER walk).
- OPC UA HTTPS, Windows support, Multi-user OIDC + roles,
  PROFINET DCP/GOOSE/SV (L2), macOS sandbox via cgo, TUI with
  bubbletea — all multi-day or operator-decision items.

## [1.27.0] — 2026-04-30

### Added

- **Seccomp arg-filter wire-up into ProfileHarvest +
  ProfileDial**. Closes the v1.26 chunk-2 follow-up: the arg-
  filter primitives are now actually installed by
  `sandbox.Load()`. `ProfileHarvest` denies `openat` with any
  of {O_WRONLY, O_RDWR, O_CREAT, O_TRUNC, O_APPEND}; `ProfileDial`
  denies `socket(AF_PACKET, …)` and `socket(AF_NETLINK, …)`.
  `ProfileExploit` left unchanged (CVE exploits sometimes
  legitimately need openat with O_CREAT for state files).
- **`pcworx` offensive write-gate** (session-level). Triple-
  confirm fence + audit row + byte relay. Per-frame PCWorx
  command gating waits for a future cycle once real-ILC test
  vectors are available; the chunk ships the protective fence
  + audit lineage now.
- **`mms` offensive write-gate** (session-level). Same shape
  as the pcworx gate. Full ASN.1 BER walk through OSI session
  + ACSE + MMS PDUs is the v1.35 candidate (MMS ACSE association
  layer in TODO-vNext.md).
- **Record & replay primitive** (`offensive/replay`). NDJSON
  proxy-session capture with HeaderEvent + ChunkEvent (RFC3339-
  microsecond timestamps + direction tags + hex payloads).
  `Recorder.Open / Wrap / WrapClient / WrapUpstream / Close` +
  `Replay(ctx, path, cb)` + `SeekHeader(path)`. Files at mode
  0600. Wire-into-each-gated-proxy is a v1.28+ task.

### Changed

- Offensive write-gate count: 7 → **9** (pcworx + mms join the
  v1.4-era set).

### Notes

- 35 new tests across the 4 chunks.
- The pcworx and mms gates ship as **session-level** with an
  explicit honest-scope note in the package docstrings: full
  per-command wire-level gating needs test vectors against real
  hardware.

### Deferred to v1.28+

- Wire record-replay primitive into each gated WriteGatedHandler.
- All v1.25-v1.26 carry-overs remain valid: GE-SRTP service-0x21,
  ProConOS, offensive plugin trios, MMS ACSE association layer,
  OPC UA HTTPS, Windows support, OIDC + roles, PROFINET L2,
  macOS sandbox (cgo), TUI bubbletea (new dep).

## [1.26.0] — 2026-04-30

### Added

- **`elsereno audit serve`** — centralised single-writer audit
  daemon listening on a Unix domain socket. Replaces the v1.15-
  chunk-4 flock at SOC scale: instead of N tail-reads per N
  appends, the daemon holds the FileWriter once + writes once.
  `audit.Server` + `audit.Client` types; `Client` implements
  `audit.Writer` so callers can swap a `FileWriter` for a daemon
  client without code changes. Wire protocol: line-delimited
  JSON (debuggable with `nc -U`). Socket file mode 0600 +
  stale-socket recovery on startup.
- **seccomp-bpf arg-level filtering primitives** (Linux) —
  closes the ADR-042 follow-up. `ArgDenyRule` type + Equal-mode
  + MaskAny-mode constructors. `ArgFilterPresets` returns the
  two canonical rules: openat-no-write (deny when flags has
  any of O_WRONLY / O_RDWR / O_CREAT / O_TRUNC / O_APPEND set)
  and socket-deny-AF_PACKET-AF_NETLINK. `CompileFilterWithArgs`
  composes the existing v1.1-chunk-6 syscall denylist with the
  new arg-level rules; arg rules run FIRST so a matching arg-
  deny returns ERRNO|EPERM before the syscall denylist gets to
  ALLOW. Cross-compiles cleanly to linux/amd64 + linux/arm64.

### Notes

- Audit-daemon: Unix-only (server uses `net.Listen "unix"`).
  Windows builds keep the v1.15-chunk-4 flock fallback.
- Seccomp arg-filter: profile integration (which preset is
  enforced for ProfileExploit / ProfileHarvest / ProfileDial)
  is deferred to v1.27. Primitives + presets ship now.
- 19 new tests across the two chunks.

### Deferred to v1.27+

- Wire seccomp arg-filter into specific sandbox profiles.
- All v1.25 carry-overs remain valid: GE-SRTP service-0x21,
  ProConOS, offensive plugin trios for v1.20+v1.21 fingerprints,
  MMS ACSE association layer, offensive pcworx/mms gates.
- macOS sandbox via `sandbox_init(3)` — operator decision (cgo).
- TUI with bubbletea — operator decision (new dep).
- Record & replay of proxy sessions.
- Windows support, OIDC + roles, PROFINET L2, OPC UA HTTPS.

## [1.25.0] — 2026-04-30

### Added

- **Two new fingerprint plugins**, default-build plugin count
  25 → 27:
  - **`pcworx`** (TCP/1962) — Phoenix Contact PCWorx runtime
    protocol used by ILC-series PLCs (ILC 130 / 150 / 170 / 191
    / 350 / 370 / 390) plus AXC F 1152/2152/3152 distributed-
    control PLCs and RFC 460R/470S Profinet-IO PLCs. 32-byte
    "IBETH01" canonical hello + banner classifier. Fail-closed
    proxy. cve_exposure:8.
  - **`mms`** (TCP/102) — IEC 61850 Manufacturing Message
    Specification. Disambiguates from S7 (which shares port
    102) via MMS-specific TSAPs in the COTP Connect-Request:
    MMS uses source/destination TSAP `00 01`; S7 uses `01 00`
    /`01 02`. COTP-CC = MMS positive; COTP-DR = likely S7.
    Fail-closed proxy. cve_exposure:9, impact_class:85
    (grid-scale: protective relays govern transmission +
    distribution circuit-breaker trips).
- **`cve_exposure` rollout to the v1.20+v1.21 fingerprint trios**
  (finsudp=5, slmp=6, gesrtp=5, knxip=6, mbustcp=4, dlms=7).
  Each value cites anchor CVEs in code comments. Closes the
  v1.24 chunk-1 carry-over.

### Stats

- 24 / 27 plugins now publish a non-zero `cve_exposure` score
  (was 16/25 post-v1.24). Remaining 3: atmodem / xot / banner.
- ~46 new tests across the 3 chunks.

### Deferred to v1.26+

- GE-SRTP service-0x21 richer firmware-version probe — needs
  real-PLC test vectors to validate the byte layout.
- ProConOS (TCP/20547) — conflicting public wire-layer
  references; needs disambig research.
- Offensive plugin trios for the v1.20+v1.21 fingerprints
  (FINS / SLMP / SRTP / KNX / M-Bus / DLMS write services).
- `elsereno audit serve` daemon (UDS).
- seccomp-bpf arg-filtering.
- macOS sandbox via `sandbox_init(3)` — operator decision
  (cgo break).
- TUI with bubbletea — operator decision (new dep).
- Record & replay of proxy sessions.
- Windows support, multi-user OIDC + roles.
- PROFINET DCP / GOOSE / SV (L2; needs CAP_NET_RAW).
- OPC UA HTTPS.

### Added

- **v1.19 chunk 3 — CWMP TransferComplete async firmware
  re-fetch**: closes the long-running v1.16 chunk-1 loose end
  by adding a post-flash supply-chain integrity check.
  TR-069 doesn't carry the SHA-256 in TransferComplete — the
  CPE just reports success/failure — so a firmware swap on
  the source server (e.g. compromised ACS staging host) can
  pass undetected if the operator only relied on the v1.13
  chunk-2 pre-flight `verify-firmware` recipe. v1.19 chunk 3
  closes this by re-fetching + hashing the URL post-flash.
  Opt-in via the new `--verify-firmware-on-complete` flag on
  `proxy listen --plugin cwmp` (off by default — async re-
  fetch isn't free; operators turn it on for high-stakes
  ISP-grade fleets). Wraps the v1.15-chunk-1 default
  TransferComplete observer in a `verifyingTransferComplete-
  Observer` that, on every successful TC carrying a resolved
  Authorisation with a non-empty AllowlistSHA256, spawns a
  goroutine that:
  (a) HTTP-fetches AllowlistURL with a caller-supplied
  timeout (default 5m via new `--verify-firmware-timeout`);
  (b) streams + SHA-256-hashes the body (no full-image
  buffering — firmware can be tens of MiB);
  (c) compares against AllowlistSHA256 (case-insensitive);
  (d) emits a `cwmp_firmware_verify` audit row with status
  `match` / `mismatch` / `unreachable` + url + expected and
  measured SHA-256 + command_key + target.
  Async — the proxy request finishes before the verification;
  network failures produce an `unreachable` audit row, not a
  missed audit. New `audit.EventCWMPFirmwareVerify` const +
  migration `00004_audit_cwmp_firmware_verify_event_type.sql`.
  Reuses the v1.13-chunk-2 `fetchFirmwareSHA256` /
  `firmwareStatusMatch|Mismatch` primitives from
  `cmd_write_gates_offensive.go`. 9 new tests covering the
  status classifier (match / mismatch / unreachable), the
  observer-skip cases (no auth / empty SHA-256 / fault path),
  defensive nil-runtime no-ops, and the chooseTransferComplete-
  Observer opt-in/opt-out switch.
- **v1.19 chunk 2 — Reload cadence dashboard panel**: surfaces
  the v1.17-chunk-5 `proxy_allowlist_reload` audit rows as a
  per-day count for the last 7 days. Operators see spikes
  during change-window activity + sustained zeroes when no
  in-process reloads happen. Reuses the
  `/api/v1/audit/cadence?event_type=proxy_allowlist_reload`
  endpoint from chunk 1; renders a text-based bar chart
  (`█` width-30 scaled to the max count) so the dashboard
  doesn't pull in a chart library. Pure dashboard addition;
  no new API surface, no new test (chunk 1's
  `TestAuditCadence_HappyPath` already covers the underlying
  endpoint).
- **v1.19 chunk 1 — Audit log API endpoint + dashboard panel**:
  closes a long-running observability gap — operators can
  finally see audit-chain entries on the dashboard without
  shelling into the host and `tail -f
  ~/.elsereno/audit.jsonl`. New
  `GET /api/v1/audit?event_type=&actor=&occurred_after=&limit=`
  returns the newest 50 (clamped [1, 500]) audit entries in
  descending occurred_at order. New
  `GET /api/v1/audit/cadence?event_type=&days=N` returns
  per-day counts for the last N days (clamped [1, 90]) — used
  by v1.19 chunk 2's reload-cadence panel + future "events
  over time" charts. New `repo.AuditEntry` /
  `repo.AuditQuery` / `repo.AuditCadence` /
  `repo.ListAuditLog` / `repo.ListAuditCadence`. Tombstoned
  rows (purged via `audit purge` per ADR-013) come back with
  `payload = null` and `tombstoned = true` so the dashboard
  can render them as `[redacted]` while preserving the chain
  entry. New "Audit feed" dashboard panel with event_type
  dropdown + actor text filter + a per-row payload excerpt
  (≤120 chars). 6 new tests in
  `internal/web/handlers/audit_test.go` covering the nil-
  querier 503, happy-path JSON envelope, invalid-int filter
  fallback, and the cadence endpoint variants.
- **v1.18 chunk 2 — Dashboard diff between runs**: closes
  another long-standing TODO-vNext item — operators running
  weekly scans can now see what changed between two runs
  without grepping JSON. New
  `GET /api/v1/findings/diff?old=<run_id>&new=<run_id>`
  returns a categorised JSON envelope with three buckets:
  `new` (in new run, no match in old), `resolved` (in old run,
  no match in new), `persisting` (in both). Match key is
  (target_id, protocol) — same exposure rediscovered on the
  next scan is "persisting" even though its DB row gets a
  fresh UUID. The Persisting bucket carries the new-run row
  so the operator sees the freshest score / factors.
  New `repo.DiffFindings` library function + new
  `RunID` filter on `repo.FindingsQuery`. Added a "Diff
  between runs" panel to the dashboard with a two-input form
  (old / new run ID) + per-bucket result tables. 9 new tests:
  6 in `internal/repo/findings_diff_test.go` covering the
  pure-bucketise logic (all-new, all-resolved, persisting,
  mixed, protocol-mismatch-doesn't-fold, both-empty); 4 in
  `internal/web/handlers/findings_test.go` covering the HTTP
  handler (nil querier → 503, missing run IDs → 400, same
  ID → 400, happy-path JSON envelope shape).
- **v1.18 chunk 1 — Dashboard CSV export from UI**: closes a
  long-standing TODO-vNext item — operators can now export
  the findings table as CSV directly from the dashboard
  instead of cobbling together `curl /api/v1/findings | jq …`
  pipelines. New `?format=csv` query parameter on
  `GET /api/v1/findings` returns `text/csv; charset=utf-8`
  with `Content-Disposition: attachment;
  filename="findings-<RFC3339>.csv"`. Body is RFC-4180 with
  the column order id, run_id, target_id, protocol,
  severity, score, created_at (RFC3339Nano UTC), factors
  (`name=value;…` semicolon-separated, factor names sorted
  alphabetically for stable diffs across exports). The
  dashboard's findings panel gains a "Download CSV (top 500)"
  link that respects the existing limit cap.
  Backwards compat: no format param → JSON envelope (the v1.2
  default), byte-identical to pre-v1.18 behaviour.
  3 new tests in `internal/web/handlers/findings_test.go`
  (CSV format / case-insensitive `format=CSV` / no-format
  default to JSON).
- **v1.17 chunk 5 — `proxy_allowlist_reload` audit event**:
  every SIGUSR1 in-process reload (introduced in chunk 4) now
  emits a dedicated audit-chain entry with the swap status
  (`ok` / `failed`), plugin, target, allow-file path, old/new
  hash-prefix correlation handles, token-generation, and (on
  failure) a one-line reason. New `audit.EventProxyAllowlist-
  Reload` const + migration `00003_audit_proxy_allowlist_
  reload_event_type.sql` extending the SQL CHECK enumeration.
  Audit emit is best-effort (a failed audit-chain write doesn't
  block the reload swap), but every SIGUSR1 firing produces
  exactly one row regardless of whether the reload succeeded.
  Operators can now grep `event_type=proxy_allowlist_reload`
  to audit reload-cadence + reject-reasons across long-lived
  proxy sessions. 2 new tests in
  `cmd_proxy_reload_offensive_test.go` (defensive nil-writer
  no-op + hash-prefix stability). The
  `internal/audit/events_test.go` migration-sync test
  automatically picks up the new event type.
- **v1.17 chunk 4 — SIGUSR1 in-process allow-file reload**:
  delivers the operator-facing in-process reload that the v1.16-
  chunk-4 token-generation foundation + v1.17 chunks 1-3 cross-
  protocol parity made possible. New `--reload-allow-file` flag
  on `proxy listen` (requires `--allow-file`) wraps the
  concrete write-gated handler in a `reloadableHandler`
  (atomic.Pointer-based). On SIGUSR1 the proxy:
  (a) re-reads the YAML allow-file; (b) reads the new confirm-
  token from a sidecar `<allow-file>.token` (0600 enforced);
  (c) builds + authorises a new handler with the new
  allowlist; (d) atomically swaps it into the wrapper. In-flight
  connections finish with the old allowlist; new connections
  use the new one. On any failure (parse error, sidecar
  permission, authorise mismatch) the old handler is preserved
  unchanged and the operator sees a structured stderr message.
  Operator workflow: edit allow-file (typically bumping
  `token_generation:`) → dry-run with new state to mint fresh
  token → write token to `<allow-file>.token` (chmod 600) →
  `kill -USR1 $pid`. Co-exists with v1.15 chunk-5 SIGHUP
  supervisor-restart pattern: SIGHUP still exits 75; SIGUSR1
  reloads in-place. 11 new tests covering wrapper delegation,
  atomic-swap semantics, sidecar-token mode enforcement,
  validation (`--reload-allow-file` requires `--allow-file`),
  fresh-opts immutability, and pass-through of plain proxy
  listen runs (no behaviour change when --reload-allow-file
  isn't set).
- **v1.17 chunk 3 — token-generation cookie cross-protocol
  rollout (Modbus / IAX2 / pbxhttp / OPC UA)**: completes the
  v1.17 token-generation parity work — every offensive write-
  gated proxy now supports the `--token-generation N` cookie.
  Each plugin gains:
  (a) a new `AllowlistHashWithGeneration` /
  `SessionMutationWithGeneration` at the top of its hash
  ladder (separator 0xFC for modbus / iax2 / pbxhttp; 0xFB
  for opcua, below the 0xFC callMethods layer);
  (b) a `TokenGeneration uint32` field on the `WriteGatedHandler`;
  (c) `--token-generation N` flag on the corresponding
  `write <plugin> dry-run` (modbus proxy-dry-run, iax2,
  pbxhttp, opcua);
  (d) shared YAML `token_generation:` field via a single
  loader-side assignment after the plugin switch (replaces
  the per-plugin if-blocks that were pushing `loadAllowFile`
  past gocyclo);
  (e) `proxy listen --token-generation N` already shared from
  chunk 1, no new flag.
  Backwards compat: every plugin's `generation=0` (default)
  hash equals the prior top-of-ladder byte-for-byte. New
  helpers `canonOPCUAAllowlist` (extracted from
  `AllowlistHashWithGeneration` for funlen) and
  `canonAllowFileOPCUACallMethods` /
  `canonAllowFileOPCUANodeIDs` (extracted from
  `buildAllowFileOPCUA` for gocyclo). 20 new tests across 4
  test files (`offensive/write/{modbus,iax2,pbxhttp,opcua}/
  tokengeneration_test.go`), each covering hash-ladder
  degradation, gen distinctness, and the E2E Authorise
  stale-rejected / fresh-accepted / prior-cycle-backwards-
  compat matrix. With this chunk, all 7 offensive write-
  gated proxies (bacnet / cwmp / sip / iax2 / pbxhttp /
  modbus / opcua) carry the same token-generation surface,
  setting the stage for a cross-protocol SIGUSR1 reload
  handler in v1.17 chunk 4.
- **v1.17 chunk 2 — SIP token-generation cookie**: extends
  the v1.16-chunk-4 BACnet / v1.17-chunk-1 CWMP token-
  generation pattern to SIP. New `AllowlistHashWithGeneration`
  / `SessionMutationWithGeneration` at the top of the SIP
  hash ladder; separator `0xFC` (below 0xFD fromDomains, 0xFE
  AORs, 0xFF prefixes). New `TokenGeneration uint32` field on
  `sip.WriteGatedHandler`. The shared `--token-generation N`
  CLI flag (registered in the session flags from chunk 1) now
  applies to `proxy listen --plugin sip` invocations too.
  `write sip dry-run --token-generation N` flag added.
  `buildAllowFileSIP` signature gains the trailing
  `tokenGeneration uint32` parameter; YAML round-trip via the
  shared `token_generation:` field. 7 new tests covering the
  hash-ladder degradation (gen=0 matches chunk-5 hash byte-
  for-byte), cryptographic distinctness, determinism, and the
  E2E Authorise stale-rejected / fresh-accepted / chunk-5-
  backwards-compat matrix.
- **v1.17 chunk 1 — CWMP token-generation cookie**: extends
  the v1.16-chunk-4 BACnet token-generation pattern to CWMP
  (TR-069). New optional `Generation uint32` arg on
  `AllowlistHashWithGeneration` /
  `SessionMutationWithGeneration` + `TokenGeneration uint32`
  field on `cwmp.WriteGatedHandler`. Folds into the session
  hash via new separator `0xFC` (below 0xFD firmware, 0xFE
  paths). Operators bump the generation when editing the
  allow-file; a stale confirm-token (minted at the prior
  generation) is rejected at `Authorise()` time. Default
  `generation=0` preserves every v1.11 → v1.12 confirm-token.
  CLI: the existing `--token-generation N` flag (v1.16+ for
  bacnet) was promoted from the BACnet-specific flag
  registrar to the shared session-flag registrar so both
  bacnet + cwmp `proxy listen --plugin <name>` invocations
  pick it up; `write cwmp dry-run --token-generation N`
  added. YAML round-trip via the existing
  `token_generation:` field in `proxyAllowFile`. 7 new tests
  (`tokengeneration_test.go`) covering the hash-ladder
  degradation, cryptographic distinctness, determinism, and
  the E2E Authorise stale-rejected / fresh-accepted /
  chunk-10-backwards-compat matrix.
- **v1.16 chunk 4 — BACnet token-generation cookie**: lays the
  cryptographic foundation for in-process allow-file reload.
  New optional `Generation uint32` field on `bacnet.Allowlists`
  + `TokenGeneration uint32` field on `bacnet.WriteGatedHandler`
  folds into the session hash via new separator `0xF5`.
  Operators bump the generation when editing the allow-file;
  a stale confirm-token (minted at the prior generation) is
  rejected at `Authorise()` time. New
  `AllowlistHashWithGeneration` /
  `SessionMutationWithGeneration` at the new top of the BACnet
  hash ladder; Generation=0 (default) preserves every v1.4 →
  v1.16-chunk-3 confirm-token. CLI:
  `--token-generation N` on `proxy listen --plugin bacnet` and
  `write bacnet dry-run`. YAML round-trip via
  `token_generation:` field. 7 new tests
  (`tokengeneration_test.go`) covering the hash-ladder
  degradation, cryptographic distinctness across generations,
  determinism, and the E2E Authorise stale-rejected /
  fresh-accepted / chunk-3-backwards-compat matrix.
  Foundational chunk: future chunks add the SIGUSR1-driven
  in-process reload + atomic allowlist swap. Other plugins
  (sip, iax2, pbxhttp, modbus, opcua, cwmp) gain the same
  field in subsequent chunks if operators need cross-protocol
  reload symmetry.
- **v1.16 chunk 3 — BACnet per-(operation, type, instance)
  LifeSafetyOperation scoping**: refines the v1.13 chunk-11
  per-operation LSO (svc 27) allowlist with a parallel per-
  target list. When the ACS includes the optional `[3]`
  objectIdentifier (operator-scoped form: "silence
  LifeSafetyPoint #3", not "silence the whole device"), the
  gate now scopes to specific (op, type, instance) tuples;
  device-wide requests (no `[3]`) fall back to the per-
  operation list. The wire parser
  `wire.ParseLifeSafetyOperationWithTarget` returns the new
  `(op, target, hasTarget, ok)` shape (existing
  `ParseLifeSafetyOperation` retained as a thin wrapper). New
  separator `0xF6` extends the BACnet hash ladder; empty
  `LSOTargets` preserves every v1.4 → v1.16-chunk-2 confirm-
  token. CLI: `--lso-target op=N;type=N;instance=N`
  (repeatable). YAML round-trip via `lso_targets:` block. 9
  new tests across `lsotarget_test.go` (hash-ladder
  degradation, wire parser including the `[3]`-bearing form,
  E2E gate matrix). Operationally important for fire-alarm
  panel deployments where "operator may unsilence
  LifeSafetyPoint #3 only" is much tighter than "operator may
  unsilence anything on this device".
- **v1.16 chunk 2 — BACnet per-(type, instance) CreateObject
  scoping**: refines the v1.13 chunk-8 per-type CreateObject
  (svc 10) allowlist with a parallel per-(type, instance) list.
  When the ACS uses the `[1]` objectIdentifier CHOICE form (the
  ACS pre-declares which exact instance the device should
  create), the gate matches against the operator's
  `AllowedCreateObjectInstances` list; the v1.13 per-type list
  remains as fallback so operators can mix grains. Per-instance
  match wins; falls back to per-type. New
  `wire.ParseCreateObjectWithInstance` returns
  `(objType, instance, hasInstance, ok)` — wire parser change is
  internal-only (`ParseCreateObject` retained as a thin wrapper
  for backwards compat). New separator `0xF7` extends the
  BACnet hash ladder; empty `CreateObjectInstances` preserves
  every v1.4 → v1.13-chunk-13 confirm-token. CLI:
  `--create-object-instance type=N;instance=M` (repeatable).
  YAML round-trip via `create_object_instances:` block. 9 new
  tests across `createobjectinstance_test.go` (hash-ladder
  degradation, wire parser, E2E gate matrix).
- **v1.16 chunk 1 — CWMP TransferComplete authorisation
  cross-reference**: closes the v1.15 chunk-1 observer half by
  correlating the CPE → ACS TransferComplete envelope with the
  prior Download authorisation that started the transfer. The
  gate records (CommandKey, DownloadURL, AllowlistURL,
  AllowlistSHA256, AuthorisedAt) at Download authorisation
  time (FIFO-bounded by `PendingDownloadCap`, default 256) and
  resolves the entry on TransferComplete. The resolved
  cross-reference is exposed via the new
  `TransferCompleteFields.Authorisation *DownloadAuthorisation`
  field; `Outcome()` classifies the envelope into one of
  `succeeded` / `failed` / `orphan_complete` / `orphan_fault`.
  Default CLI observer enriches its stderr log line with
  `outcome=`, `download_url=`, `allowlist_sha256=`, and
  `authorised_at=` fields. Orphan rows surface CPE reports for
  CommandKeys we never authorised (suspicious) for operator
  alerting. Resolution is one-shot — a duplicate or replayed
  TransferComplete sees `Authorisation=nil` on the second hit.
  9 new tests across `transfercomplete_test.go` (E2E
  Download → TransferComplete observer flows) and a new
  `pendingdownload_test.go` (unit tests for cap eviction +
  duplicate-key handling + extractor parser).

## [1.15.0] — 2026-04-26

Five-chunk cycle covering loose-end closure on multiple
surfaces: CWMP firmware-pin observability, operator-UX
scanning, threat-intel interop, audit concurrency hardening,
and supervisor-driven reload.

### Added

- **CWMP TransferComplete observer**: `WriteGatedHandler`
  gains an opt-in `OnTransferComplete` callback that fires
  when CPE → ACS TransferComplete envelopes traverse the gate.
  Default CLI observer emits structured stderr log lines
  (`status=ok|fault command_key=… fault_code=…`). Closes
  the v1.12 chunk-10 firmware-pin loop.
- **`elsereno discover --auto <CIDR>`**: TCP-connect sweep
  iterates the CIDR + probes the well-known port of every
  registered plugin, emits responsive (host, port) pairs
  as NDJSON or `host:port` list. Pipe-friendly with
  `scan --input list:-`.
- **STIX 2.1 export**: new `--output-format stix` emits
  findings as a STIX bundle (ipv4/ipv6-addr SCO + network-
  traffic SCO + observed-data SDO per finding). Deterministic
  UUIDv5 IDs for diff-based regression testing. MISP /
  OpenCTI / ThreatBus ingest-ready.
- **SIGHUP reload-style exit**: proxy listen distinguishes
  SIGHUP (exit 75 / EX_TEMPFAIL — supervisor restart signal)
  from SIGINT/SIGTERM (exit 0 — clean stop). Operator
  workflow: edit allow-file, mint fresh confirm-token,
  `kill -HUP` → systemd / runit / s6 restarts with new config.

### Changed

- **Audit chain cross-process merge** via `unix.Flock(LOCK_EX)`.
  The `Append`/`appendVerbatim` read-then-write critical
  section is now guarded by an exclusive flock + tail-resume,
  so two ElSereno processes appending to the same
  `~/.elsereno/audit.jsonl` serialise + merge cleanly. Linux
  + macOS only; Windows stub returns nil (Windows support
  is a v1.16+ cross-cutting cycle).

### Tooling / docs

- New `internal/outputs/stix` + `internal/audit/flock_unix.go`
  + `internal/audit/flock_windows.go` packages.
- `cmd_discover.go` adds the new top-level subcommand.
- Proxy listen long-help text gains a "SIGHUP reload via
  supervisor restart" section.
- `docs/protocols/cwmp.md` gains a "TransferComplete observer
  (v1.15+)" section.

### Deferred to v1.16+

- BACnet per-instance Create + per-object LSO refinements.
- 12 legacy ICS protocols (PROFINET, CoDeSys, Omron FINS, …).
- TUI bubbletea, Windows support, OIDC + roles, record-&-
  replay.
- In-process allow-file reload (alternative to the chunk-5
  supervisor-restart pattern).

## [1.14.0] — 2026-04-26

Four-chunk cycle covering operator-requested IPv6 cross-
cutting work (request 2026-04-25). Audit + canonicalise IPv6
paths across proxy listen, dry-run, scan input, scope-gate,
and target-dedup layers. Two real bugs fixed; rest is
contract-pinning tests on infrastructure that was already
correct.

### Added

- New `internal/netutil` package with `IsLoopbackHostPort`,
  `CanonicalHostPort`, `ParseAddrPort` helpers — replaces
  fragile substring-based loopback detection with delegation
  to `netip.ParseAddrPort` + `Addr.IsLoopback()`.
- `canonicaliseTarget` helper applied at every CLI parse
  boundary (proxy listen + 6 dry-run commands + BACnet
  runner) — IPv6 longform/uppercase variants now collapse
  to the canonical RFC 5952 form before flowing into
  hashes / byte-for-byte compares / YAML emits.
- `scan --input internetdb:` dispatcher case (was missing
  in v1.13 chunk 1 — CLI accepted the prefix but
  `readTargets` errored as "unknown input kind").
- `stripIPv6Brackets` helper at the InternetDB CLI boundary —
  `--input internetdb:[2001:db8::1]` now works, mirroring
  the host:port bracket convention used by `--target`.
- 50+ new tests across the cycle (netutil unit + per-plugin
  hash equivalence + dispatcher regression guard + scope/
  dedupe IPv6 contract).

### Changed

- `cmd_serve.go` `isLoopbackAddr` delegates to
  `netutil.IsLoopbackHostPort` — now correctly recognises
  IPv6 longform `[0:0:0:0:0:0:0:1]:port`, zone-scoped
  `[::1%lo0]:port`, and IPv4 anywhere-in-127/8.

### Backwards compat

- IPv4 forms unchanged (already canonical).
- IPv6 already-canonical forms unchanged.
- Only operators using IPv6 longform / uppercase hex need to
  re-mint confirm-tokens.

### Deferred to v1.15+

- CWMP TransferComplete-side SHA-256 verification.
- 12 legacy ICS protocols (PROFINET, CoDeSys, Omron FINS, …).
- BACnet per-instance Create + per-object LSO refinements.
- Big-picture: TUI, Windows, OIDC + roles, record-&-replay.

## [1.13.0] — 2026-04-26

Thirteen-chunk cycle. **Closes every BACnet mutating service**
(svc 7/8/9/10/11/15/16/17/20/27) with wire-level per-target-or-
state allowlists. Plus CWMP polish + operator-UX improvements.

### Added

- **All 9 BACnet mutating services gated at wire-level**:
  - svc 7 AtomicWriteFile — per-File-instance (`--awf-file N`).
  - svc 8 AddListElement + svc 9 RemoveListElement — shared
    per-(object, property) allowlist (`--list-element
    type=N;instance=M;property=P`).
  - svc 10 CreateObject — per-type (`--create-object-type N`).
  - svc 11 DeleteObject — per-(type, instance)
    (`--delete-object type=N;instance=M`).
  - svc 16 WritePropertyMultiple — per-(type, instance,
    property) batch walker (`--object` shared with svc 15).
  - svc 17 DeviceCommunicationControl — per-state enableDisable
    enum (`--dcc-state N`).
  - svc 20 ReinitializeDevice — per-state reinitializedStateOfDevice
    enum (`--reinit-state N`).
  - svc 27 LifeSafetyOperation — per-operation
    BACnetLifeSafetyOperation enum (`--lso-op N`).
- **InternetDB bulk lookup** (`--input internetdb:file:<path>`
  + `internetdb:-` stdin).
- **CWMP firmware pre-flight verifier**
  (`elsereno-offensive write cwmp verify-firmware`).
- **CWMP RPC-name case-warning** in dry-run (TR-069 §A.4
  case-sensitivity guard).
- **CWMP-over-TLS operator recipe** (docs only — nginx /
  HAProxy / Caddy front-proxy patterns).
- **Triage `utility` bucket** — fourth priority bucket
  between `strategic` and `routine` for inventory-style
  findings (banner/atmodem fingerprints).

### Changed

- BACnet `Allowlists` bundle struct (chunk 10) consolidates
  every per-service dimension into a single arg.
- `objectListGatesAllow` split into `propertyTupleGatesAllow`
  + `objectIdentityGatesAllow` (chunk 13) for gocyclo.
- `buildAllowFileBACnet` takes a `buildAllowFileBACnetInputs`
  struct (chunk 13) instead of 9 positional args.
- Hash ladder: 8 separator bytes (0xF8 list-elements →
  0xFF per-property objects) preserve operator confirm-tokens
  across the upgrade.
- `make sec` exit-0 (`b611f5c` swapped 18 `//nolint:gosec` to
  native `// #nosec G<NNN>` markers).

### Tooling / docs

- New `man/src/man1/elsereno.1.md` — first man1 page.
- 5 new per-protocol pages under `docs/protocols/` (sip, iax2,
  pbxhttp, cwmp, opcua).
- TODO.md trimmed 203 → 65 lines.
- TODO-vNext.md restructured with shipped-archive section.

### Deferred to v1.14+

- IPv6 cross-cutting support (operator-requested 2026-04-25).
- CWMP TransferComplete-side SHA-256 verification.
- BACnet per-instance Create + per-object LSO scoping (currently
  type-only / operation-only).
- 12 legacy ICS protocols (PROFINET, CoDeSys, Omron FINS, …).
- SIGHUP reload, `discover --auto <CIDR>`, TUI, Windows, OIDC
  + roles, STIX 2.1 export, record-&-replay.

## [1.12.0] — 2026-04-25

### Added

- **Per-object / per-path scoping across all 7 write-gated
  proxies.** Each existing gate gains a finer dimension:
  CWMP `--param-prefix` (chunk 1), OPC UA multi-WriteValue
  (chunk 2), OPC UA String/GUID/ByteString NodeID (chunk 3),
  Modbus structured `--write unit=N;fc=M;start=A;end=B`
  (chunk 4), SIP `--from-domain HOST` (chunk 5), OPC UA
  `--call-method object=…;method=…` (chunk 6), BACnet
  `--object type=N;instance=M;property=P` for WriteProperty
  (chunk 7), CWMP `--firmware url=…;sha256=…` for Download
  (chunk 10).
- **Input pagination** across all 5 paid attack-surface
  providers (chunk 8) — `SearchPaged(ctx, query, totalLimit)`
  accumulates up to 1000 hits across pages. Censys uses
  cursor-based pagination via `result.links.next`; the
  others use `?page=N`.
- **Shodan InternetDB** (chunk 9) — 6th attack-surface
  provider, no-key, free, single-IP lookup. CLI:
  `--input internetdb:<ip>`. Rate-limited upstream to ~10 rps.

### Changed

- All 7 gates' `AllowlistHash*` functions gain "With<Dimension>"
  companions. Backwards-compat ladder: empty new dimension
  degrades to the prior-version hash; existing operator
  confirm-tokens remain valid.
- 100 new tests cycle-wide. Hash separators reserved per
  dimension (CWMP `0xFD` firmware / `0xFE` param-path; OPC UA
  `0xFC` CallMethod / `0xFD` canonical NodeID / `0xFF`
  numeric NodeID; SIP `0xFD` from-domain / `0xFE` AOR / `0xFF`
  prefix; BACnet `0xFE` delete-objects / `0xFF` per-property
  objects).

### Deferred to v1.13+

- Per-object scoping for the rest of the BACnet mutating
  services (now partially shipped on main: WPM svc 16 +
  DeleteObject svc 11 in v1.13 chunks 3 + 7).
- Bulk InternetDB lookup (now shipped on main: v1.13 chunk 1).
- CWMP TransferComplete-side SHA-256 verification (still
  pending).
- SIGHUP reload of proxy listen allowlist.

## [1.11.0] — 2026-04-24

### Added

- **CWMP offensive proxy** — `offensive/write/cwmp`. Completes
  the TR-069 story. v1.4 chunk 5 shipped the fingerprint (17
  plugins, 15 ACS vendors); this ships the matching offensive
  gate. Use case: operator sits between an ACS and a fleet of
  CPEs during change windows and allowlists the SOAP RPCs
  they're authorising.
- **`AllowedRPC{Name string}`** opt-in type. Names are case-
  sensitive per TR-069 §A.4.
- **`AllowlistHash(target, allowed)`** + **`SessionMutation`**
  — standard ADR-040 shape.
- **`canonicaliseRPC`** helper — strips namespace prefix
  (`cwmp:` / `cwmp-1-0:` / `cwmp-1-2:`) and whitespace; case
  preserved.
- **`alwaysSafeRPCs` set (14 entries)** — `GetParameter{Names,
  Values,Attributes}` + Response variants, `GetRPCMethods`,
  `Inform{,Response}`, `TransferComplete{,Response}`,
  `AutonomousTransferComplete`, `Kicked{,Response}`, `Fault`.
  These always pass.
- **`elsereno write cwmp dry-run --rpc <Name>`** CLI,
  repeatable.
- **`elsereno proxy listen --rpc <Name> --plugin cwmp`** CLI.
- **YAML `rpcs:` field** in `proxyAllowFile` — round-trips
  through emit → load.

### Changed

- Write-capable RPCs (SetParameterValues, Reboot, Download,
  FactoryReset, AddObject, DeleteObject, Upload,
  ScheduleInform, ScheduleDownload, ChangeDUState,
  CancelTransfer, SetParameterAttributes) now require explicit
  allowlist. Empty allowlist → all write-capable RPCs refused;
  always-safe RPCs still pass.
- Refusal emits HTTP 200 OK + CWMP SOAP Fault body with
  FaultCode 9001 "Request denied" (TR-069 Annex A spec-
  conformant) + `X-Elsereno-Gate-Reason` header. ACS code
  parses the rejection as an app-level error rather than a
  transport glitch.
- Non-POST (GET/HEAD/OPTIONS) requests bypass the SOAP parser
  entirely — TR-069 proper is POST-only; non-POST is for ACS
  status / health endpoints.
- 7 offensive write-gated proxies in the default build (was
  6). List: modbus, opcua, sip, iax2, pbxhttp, bacnet, cwmp.

### Deferred to v1.12+

- Per-parameter-path allowlist for `SetParameterValues`.
- Firmware-URL allowlist for `Download` (URL + SHA-256 pin).
- RPC-name case-warning in dry-run (flag unknown names).
- Batch-RPC deferred-response routing.
- CWMP-over-TLS (`:7548`) — already works transparently as
  long as the proxy terminates TLS locally, but deserves an
  explicit operator recipe.
- SIGHUP reload (still needs redesign).

## [1.10.0] — 2026-04-24

### Added

- **SIP REGISTER AOR allowlist** — anti-registration-hijack
  twin of v1.9 chunk 5's INVITE prefix gate. Where the INVITE
  prefix controls WHERE calls can go (toll-fraud mitigation),
  this gate controls WHO can register a binding (registration-
  hijack mitigation). Closes the second of the two main PBX-
  abuse vectors.
- **`AllowedAOR{AOR string}`** opt-in type on
  `offensive/write/sip.WriteGatedHandler.AllowedAORs`. Exact-
  match (not prefix): stolen creds for `alice@pbx` shouldn't
  also let an attacker register `admin@pbx`.
- **`AllowlistHashWithAORs(target, methods, prefixes, aors)`**
  — new hash that mixes all three allowlist dimensions.
  Backwards-compat: empty aors → v1.9 hash; empty aors AND
  empty prefixes → v1.4 hash. 0xFE separator for the AORs
  block (distinct from 0xFF prefix separator and ASCII method
  bytes).
- **`SessionMutationWithAORs`** factory; `Authorise()` now
  calls this variant.
- **`canonicaliseAOR`** helper — strips angle brackets, URI
  parameters, `sip:`/`sips:`/`tel:` scheme; lowercases host;
  preserves user-part case per RFC 3261 §19.1.1.
- **`elsereno write sip dry-run --aor <AoR>`** CLI flag,
  repeatable.
- **`elsereno proxy listen --aor <AoR>`** CLI flag,
  repeatable.
- **YAML `aors:` field** in `proxyAllowFile` — round-trips
  through emit → load back to `proxyListenOpts.aors`.

### Changed

- `buildAllowFileSIP` signature extended from 3-arg to 4-arg
  `(target, methods, toPrefixes, aors)`. All 3 existing test
  callers updated.
- `forwardOne` path adds a parallel `REGISTER + AOR list`
  branch to the existing `INVITE + prefix list` branch.
  Failed `registerAORAllowed` emits 403 + `X-Elsereno-Gate-
  Reason: AOR not in session allowlist (REGISTER hijack
  guard)`.

### Deferred to v1.11+

- CWMP offensive proxy (SOAP RPC allowlist).
- BACnet per-object allowlist (ASN.1 BER).
- OPC UA String / Guid / ByteString NodeID encodings.
- OPC UA multi-node per WriteRequest.
- OPC UA CallRequest per-object allowlist.
- Modbus structured `writes:` YAML (unit + FC + addr range).
- SIGHUP reload of proxy listen allowlist.

## [1.9.0] — 2026-04-24

Five chunks that close carry-overs, complete the attack-surface
input story, and add a concrete toll-fraud mitigation.

### Added

- **OPC UA NodeID YAML round-trip.** The `--allow-file` emitter
  + loader now persist per-NodeId allowlist entries as
  structured `node_ids:` entries. Closes the v1.6 → v1.8 gap
  where the per-NodeId gate had CLI support but the YAML
  round-trip silently dropped NodeIDs.
- **`elsereno write modbus proxy-dry-run`** — session-level
  dry-run for the Modbus write-gate. Closes the write-surface
  asymmetry (now all 6 gated plugins — sip/iax2/pbxhttp/opcua/
  bacnet/modbus — have proxy-session dry-runs).
- **`elsereno scan --input <provider>:<query>`** — CLI wire-up
  for the 4 attack-surface input clients (shodan, censys, fofa,
  zoomeye). Credentials via `--api-creds-file <path.yaml>` with
  0600 permission enforcement and strict unknown-field
  rejection.
- **`internal/inputs/onyphe`** — 5th provider. ONYPHE (onyphe.io)
  uses OQL query syntax embedded in the URL path + `bearer`
  auth header. Wired into `scan --input onyphe:<q>`.
- **SIP INVITE To-URI prefix allowlist.** New opt-in field
  `WriteGatedHandler.AllowedToURIPrefixes` on the SIP
  write-gate. When non-empty, INVITE passes only when the To:
  header's URI user-part starts with one of the operator-
  supplied prefixes. Canonical use-case: allow INVITE but only
  to whitelisted destinations (e.g. "+34", "+44") while
  rejecting "+900" premium-rate prefixes that are favourite
  toll-fraud vectors. Other methods (REGISTER, MESSAGE, …)
  unaffected.

### Changed

- `proxyAllowFile` YAML schema gains two v1.9 fields:
  `node_ids:` (list of `{namespace, identifier}`) for opcua +
  `to_prefixes:` (string list) for sip. Both `omitempty` so
  v1.4-v1.8 emitted files stay backwards-compatible.
- `buildSIPHandler` + `buildOPCUAHandler` now pass the new
  optional fields (`AllowedToURIPrefixes`, `AllowedNodeIDs`)
  through to the write-gate.
- SIP + OPC UA `AllowlistHash` gain `WithPrefixes` /
  `WithNodeIDs` companions that degrade to the v1.4 / v1.6
  hash when the new dimension is empty — existing operator
  tokens remain valid.

### Deferred to v1.10+

- SIP REGISTER AOR allowlist (sister to chunk 5's INVITE prefix
  list; blocks registration hijack).
- Modbus per-(unit, fc, addr-range) structured YAML (closes
  chunk 2's `--unit`/`--address-*` + `--emit-allow-file`
  incompatibility).
- OPC UA multi-WriteValue allowlist (v1.6 + v1.9 chunk 1 check
  the first WriteValue only).
- OPC UA String/Guid/ByteString NodeID encodings (chunk 1 is
  numeric-only).
- OPC UA CallRequest per-object allowlist.
- BACnet per-object allowlist (ASN.1 BER parsing).
- CWMP offensive proxy (SOAP RPC allowlist — fingerprint shipped
  in v1.4).

## [1.8.0] — 2026-04-23

### Added

- **`internal/inputs/fofa`** — FOFA (fofa.info) attack-surface
  input client, operator-requested. Requires both `email` +
  `apiKey` (unlike Shodan's single key). `Search` base64-
  encodes the query per FOFA's `qbase64` convention, requests
  `fields=host,ip,port` for a stable row shape, maps rows to
  `core.Target{Address, Port}`. `ErrNoCredentials` +
  `ErrAPIError` typed sentinels.
- **`internal/inputs/zoomeye`** — ZoomEye (zoomeye.org)
  attack-surface input client, operator-requested. Single API
  key delivered via `API-KEY` HTTP header so credentials
  don't leak through URL logs. 1-based paging. `ErrNoAPIKey`
  sentinel.

### Notes

- Both clients are **library-level only**, matching the
  existing Shodan + Censys precedent. Neither is wired into
  the `scan --input <kind>` dispatch yet — that's a v1.9
  design decision (extend `--input fofa:<query>` vs a new
  `elsereno search` verb vs vault-integration via
  `elsereno creds store <provider>`).

### Deferred to v1.9+

- CLI wire-up for FOFA + ZoomEye (see design options above).
- ONYPHE input client (also in `TODO-vNext.md`).
- Modbus proxy-session dry-run (v1.7 carry-over).
- BACnet per-object allowlist.
- SIP To-URI E.164 prefix allowlist for INVITE.
- REGISTER AOR allowlist.
- CWMP offensive proxy.
- SIGHUP reload of proxy listen allowlist.

## [1.7.0] — 2026-04-23

### Added

- **`elsereno write <plugin> dry-run --emit-allow-file PATH`** —
  writes the canonical YAML allow-file that pairs with v1.6
  `proxy listen --allow-file`. Path `-` writes to stdout; any
  other path is created/truncated with 0600 permissions.
  Round-trip: the file emitted plugs directly into `proxy
  listen --allow-file` without further editing.
- **`elsereno write opcua dry-run`** — OPC UA proxy-session
  token minting. Supports `--service <TypeID>` + optional
  `--node-id ns=N;i=M` (repeatable) for the v1.6 per-NodeId
  gate. PayloadHash is computed via `SessionMutationWithNodeIDs`
  when NodeIDs are present.
- **`elsereno write bacnet dry-run`** — BACnet/IP proxy-session
  token minting. Takes `--service-choice <N>` (0-255) for the
  v1.4 chunk 6 confirmed-service allowlist.
- Shared helpers for operator UX: `parseNodeIDFlag("ns=N;i=M")`,
  `canonUintList`, `canonNodeIDs`, `canonUints`.
- **TODO**: FOFA (fofa.info) + ZoomEye (zoomeye.org) input
  integrations are tracked in `TODO-vNext.md` for a future
  cycle. Operator-requested 2026-04-23.

### Changed

- `proxyAllowFile` struct gained `,omitempty` YAML tags on
  per-plugin fields so dry-run-emitted YAML only contains the
  fields relevant to the selected plugin.
- The write command surface is now symmetric across the five
  proxy-session-capable plugins (sip / iax2 / pbxhttp / opcua
  / bacnet). Modbus proxy-session dry-run is a v1.8 carry-over
  because the existing `write modbus` CLI shape is per-request
  (not per-session).

### Deferred to v1.8+

- Modbus proxy-session dry-run.
- Per-NodeId persistence in the YAML allow-file (v1.7 emitter
  only serialises `services:` for opcua; `node_ids:` wire-up
  pending).
- Runtime reload of the proxy listen allowlist (SIGHUP).
- BACnet per-object allowlist (ASN.1 BER parsing).
- SIP To-URI E.164 prefix allowlist for INVITE.
- REGISTER AOR allowlist.
- CWMP offensive proxy (SOAP RPC allowlist).
- FOFA / ZoomEye input integrations.

## [1.6.0] — 2026-04-23

### Added

- **`elsereno proxy listen --allow-file <path.yaml>`** — load
  plugin + target + per-plugin allowlist from a YAML file
  instead of long command-line flag sets. Unknown fields are
  rejected (`yaml.NewDecoder.KnownFields(true)`) so typos like
  `method:` (should be `methods:`) fail noisily. Schema per
  plugin: `methods` (sip), `subclasses` (iax2), `allow`
  (pbxhttp), `functions` (modbus), `services` (opcua),
  `service_choices` (bacnet).
- **OPC UA per-NodeId allowlist** (`offensive/write/opcua`) —
  optional second-stage gate that authorises WriteRequest MSGs
  only when the first WriteValue's NodeId matches an operator-
  supplied list of `{Namespace, Identifier}` pairs. The v1.2
  service-TypeID allowlist still fires first; the NodeID check
  is strictly a *tightening*. Supports TwoByte / FourByte /
  Numeric NodeId encodings; rarer encodings (String / Guid /
  ByteString) cause fail-closed refusal when per-node gating
  is active.
- **`internal/protocols/opcua/wire.WriteRequestFirstNode`**
  parser — walks past the UA RequestHeader + NodesToWrite
  array prefix to extract the first NodeId.
- **`AllowlistHashWithNodeIDs`** and **`SessionMutationWithNodeIDs`**
  on `offensive/write/opcua` — new factories that mix NodeIDs
  into the session PayloadHash.

### Changed

- OPC UA `WriteGatedHandler.Authorise()` now calls
  `SessionMutationWithNodeIDs` instead of the v1.2
  `SessionMutation`. For operators who don't set
  `AllowedNodeIDs`, this is a no-op: the hash degrades to
  the v1.2 `AllowlistHash(target, services)` and existing
  confirm-tokens remain valid.

### Deferred to v1.7+

- OPC UA String / Guid / ByteString NodeId matching.
- OPC UA multi-node-per-WriteRequest allowlist (today only
  the first WriteValue is checked).
- OPC UA CallRequest per-object allowlist.
- BACnet per-object allowlist (ASN.1 BER parsing).
- SIP To-URI E.164 prefix allowlist for INVITE.
- REGISTER AOR allowlist.
- CWMP offensive proxy.
- Runtime reload of the proxy listen allowlist (SIGHUP).
- `elsereno write <plugin> dry-run --emit-allow-file`.

## [1.5.0] — 2026-04-23

### Added

- **`elsereno proxy listen`** (offensive build) — runs any of
  the six v1.4 write-gated handlers inline against a local
  TCP listener. The operator workflow is finally end-to-end:
  mint a confirm-token with `elsereno write <plugin> dry-run
  --vault-passphrase-file …`, then run `elsereno proxy listen
  --plugin <plugin> --target h:p --listen L:P <allowlist
  flags> --accept-writes --confirm-target h:p --confirm-token
  <hex> --vault-passphrase-file /path` to serve a gated
  session until SIGINT / SIGTERM. Supported plugins:
  - `--plugin sip --method INVITE …`
  - `--plugin iax2 --subclass NEW …`
  - `--plugin pbxhttp --allow POST:/admin/config.php …`
  - `--plugin modbus --function 6 …`
  - `--plugin opcua --service 673 …`
  - `--plugin bacnet --service-choice 15 …`
- **First end-to-end integration test** of the gated proxy
  stack: fake SIP origin + `proxy.Server` + gated handler +
  real client — asserts that allowlisted methods reach the
  origin while refused methods get a canonical 405 without
  ever leaving the proxy.

### Changed

- The `proxy` command (previously a planned-stub returning
  EX_TEMPFAIL 75) now exposes real subcommands in the
  offensive build. Default-build behaviour is unchanged: the
  command still returns the stub's "planned" message.

### Deferred to v1.6+

- OPC UA per-NodeId allowlist.
- BACnet per-object allowlist (ASN.1 BER parsing).
- SIP To-URI E.164 prefix allowlist for INVITE.
- REGISTER AOR allowlist.
- CWMP offensive proxy.
- `--allow-file` for YAML / JSON allowlist files.
- Runtime reload (SIGHUP).

## [1.4.0] — 2026-04-23

### Added

- **Offensive SIP write-gate** (`offensive/write/sip`, build-
  tag `offensive`). Replaces the default deny-all SIP proxy
  with a method-allowlist that lets operators use ElSereno as
  a gated SIP relay. Always-safe methods (OPTIONS / ACK / BYE
  / CANCEL / PRACK) always pass; gated methods (INVITE,
  REGISTER, MESSAGE, SUBSCRIBE, NOTIFY, REFER, PUBLISH,
  UPDATE, INFO) require explicit allowlist. Refusal is a
  canonical `SIP/2.0 405 Method Not Allowed` with an Allow:
  header.
- **Offensive pbxhttp write-gate** (`offensive/write/pbxhttp`).
  (method, path) allowlist for HTTP admin UIs. GET/HEAD/OPTIONS
  always pass; CONNECT always refused. Refusal decision tree:
  405 if the method isn't in the allowlist; 403 if the method
  matches but the path doesn't.
- **Offensive iax2 write-gate** (`offensive/write/iax2`). UDP
  per-datagram IAX2 subclass allowlist. Mini-frames (audio)
  and non-IAX media frames always pass. Gated subclasses:
  NEW (call setup), REGREQ (registration), AUTHREP, ACCEPT.
  Refusal is a HANGUP full-frame — the universal IAX call-
  teardown signal.
- **Offensive BACnet write-gate** (`offensive/write/bacnet`).
  UDP per-datagram BACnet confirmed-service allowlist. Closes
  the v1.2 carry-over where BACnet's Handle loop was stuck at
  session-primitives because the generic TCP proxy framework
  didn't apply. Always-passes unconfirmed-requests, acks /
  errors / rejects / aborts, and confirmed-reads; gates
  WriteProperty / WritePropertyMultiple / AtomicWriteFile /
  AddListElement / RemoveListElement / CreateObject /
  DeleteObject / ReinitializeDevice / DeviceCommunicationControl
  / LifeSafetyOperation. Refusal is a BVLC-wrapped Abort-PDU
  with ASHRAE 135 §20.1.9 reason 5 (security-error).
- **CLI dry-run for all three PBX gated proxies.** New
  subcommands `elsereno write sip dry-run`, `write iax2
  dry-run`, `write pbxhttp dry-run`. Each prints the
  SessionMutation PayloadHash + canonicalised allowlist; with
  `--vault-passphrase-file`, also mints the expected confirm-
  token the operator pastes into the eventual `proxy listen`
  verb.
- **`cwmp` plugin** — TR-069 / CWMP ACS fingerprint on port
  7547/tcp. Identifies 15 ACS implementations including
  GenieACS, FreeACS, Axiros (AXACS / AX-MDM), Nokia Altiplano,
  Huawei FusionHome, Broadcom BroadWorks, Cisco Prime, ADB,
  Friendly TR-069 Simulator, interaCMS, Netopia, create-net,
  plus generic open-ACS and TR-069 markers. VendorRisk tiers
  80-90 (exposed ACS is always a finding — the 2016 Deutsche
  Telekom / Mirai port-7547 outage is the cautionary reference).
- **`internal/protocols/bacnet/wire/service.go`** — ASHRAE 135
  APDU classification helpers used by the BACnet write-gate.
  APDUType enum, ConfirmedService enum (Table 20-7),
  IsMutatingConfirmedService predicate, BuildAbortPDU helper.

### Changed

- Plugin count in the default build: **16 → 17** (+cwmp).
- Offensive write-gated proxies: **2 → 5** (+ sip, iax2,
  pbxhttp, bacnet alongside the existing modbus and opcua).
- The v1.2 BACnet carry-over is resolved: BACnet no longer
  ships with only session primitives; it has a full wire-level
  UDP gate.

### Deferred to v1.5

- `proxy listen` CLI verb: promote the existing stub to
  actually run the gated handlers inline against a real
  listener.
- OPC UA per-NodeId allowlist (tighter gate than the service-
  TypeID-level of v1.2).
- BACnet per-object allowlist (ASN.1 BER parsing).
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

## [1.3.0] — 2026-04-22

### Added

- **PBX discovery cycle.** Three new protocol plugins collectively
  identify 15 PBX brands across the canonical PBX attack surfaces,
  bringing the default build to **16 protocol plugins**.
- **`pbxhttp`** plugin — HTTP(S) PBX admin-page fingerprint on
  443 (also 80 / 8080 / 8088 / 5001 / 8443 via Scheme override).
  Single GET to `/` with a browser-like User-Agent; classifies
  response Server / HTML `<title>` / body against a priority-
  ordered 15-vendor matcher (FreePBX, PBXact, 3CX, Yeastar,
  Cisco UCM, Avaya, Mitel, Grandstream, Fanvil, Yealink, Asterisk
  HTTP Manager, Switchvox, Elastix, FreeSWITCH, plus unknown
  PBX-likely heuristic). `protocol_risk` tiers 70–90 by vendor
  class (attack-ripe / enterprise / SOHO / gateway / unknown).
  Self-signed cert tolerance (`InsecureSkipVerify=true` default)
  for fingerprinting use-case; gosec waiver documented in code.
- **`iax2`** plugin — Asterisk's native binary UDP protocol on
  port 4569. Minimal RFC 5456 full-frame parser (12-byte header;
  FrameType + IAXSubclass enums). Probe sends a random-call
  number NEW, classifies reply by subclass: ACCEPT / AUTHREQ /
  REJECT / HANGUP / PING / PONG / REG\* all confirm IAX2 →
  `protocol_risk=90`. ACCEPT triggers a polite HANGUP so the
  remote dialogue table doesn't grow. Mini-frame-length-
  mismatch guard prevents HTTP bytes (0x48 = 'H' has high bit 0
  → looks like a mini-frame) from falsely confirming IAX2.
- **`sip`** plugin — SIP OPTIONS probe on 5060 UDP+TCP with a
  15-vendor matcher: Asterisk, FreePBX, 3CX, Cisco UCM, Cisco
  SIP Gateway, Mitel (+ ShoreTel), Avaya (+ IP Office), Yeastar,
  Grandstream, Fanvil, Yealink, Kamailio, OpenSIPS, FreeSWITCH,
  SER. DenyAll proxy emits a canonical `SIP/2.0 403 Forbidden`
  with `Server: ElSereno proxy (read-only)`.

### Changed

- Plugin count in the default build: **13 → 16**. Plugin list
  now includes `iax2`, `sip`, `pbxhttp` alongside the existing
  atg / atmodem / bacnet / banner / dnp3 / enip / fox / hartip /
  iec104 / modbus / opcua / s7 / xot.

### Deferred to v1.4

- Offensive write-gated proxies for SIP / IAX2 / pbxhttp (the
  default variants deny all; INVITE / HANGUP / admin-API
  allowlist variants are v1.4).
- TR-069/CWMP fingerprint on 7547/tcp.
- VoIP-SIP dial backend subprocess (`elsereno-dial-voip-sip`).
- HTTP paths beyond `/` for pbxhttp (`/admin/config.php`,
  `/webclient/`, `/ccmadmin/`, etc. for vendor-specific recall).

## [1.2.0] — 2026-04-22

### Added

- **DB-backed dashboard panels**: new `findings`, `triage`, and
  `runs` panels on the overview page, plus `/api/v1/findings`,
  `/api/v1/runs`, `/api/v1/triage` endpoints. Fetch on page
  load + re-fetch on SSE signals (500 ms debounce). Without
  `DATABASE_URL` the endpoints return 503 and the panels
  render a clear "backend unavailable" message.
- **`internal/audit.DBWriter`** persists the audit chain to
  Postgres, preserving the same chain invariant as FileWriter.
  Reserves BIGSERIAL IDs via `nextval` before INSERT so the
  JCS hash is computed once.
- **`audit.MultiWriter`** + `FileMirror` + `DBMirror` —
  fan-out from one primary chain owner to N mirrors. Primary
  error halts fan-out; mirror error surfaces without
  reverting the primary insert.
- **`audit.SyncFromFile(ctx, path, target, existingIDs)`** —
  bootstrap a fresh DB from an existing JSONL chain. Validates
  every prev_hash + entry_hash, skips IDs already in target,
  idempotent + tamper-detecting.
- **OPC UA write gating** (`offensive/write/opcua/`): service-
  layer allowlist on Write (TypeID 673) and Call (704)
  requests. Refusal is a UA ServiceFault with StatusCode
  BadUserAccessDenied (0x80100000) — parseable by real UA
  clients.
- **Full wire-level Handle loops** for DNP3, IEC-104, HART-IP,
  ATG Veeder-Root, and Fox. Each gate refuses disallowed
  operations with a protocol-native error frame
  (DNP3 IIN2 FUNC_NOT_SUPP, IEC-104 I-format COT=47,
  HART response code 0x40, Veeder-Root NAK 9999FF1B,
  Fox `fox a 0 -1 fox denied\n`).
- **Dial backend interface** (`offensive/dial/backend/`):
  `Backend{Name, Deliver, Close}` + `Disposition` enum.
  Two backends ship: `Mock` (CI-safe scriptable) and
  `ATModem` (Hayes AT over any io.ReadWriter).
- **`/admin/security` CSP-nonce fix**: inline styles on the
  security self-audit page now honour the per-request CSP
  nonce (same treatment the overview page got in v1.1).
- **`/readyz` real DB ping** when a pool is wired, 503 on DB
  failure, adds `uptime_s` field.
- **Operator manual pack**: `docs/manual/elsereno-manual.md`
  (400+ lines, all 13 protocols, Shodan/Censys/nmap input
  recipes, scoring, offensive verbs, detection signatures,
  troubleshooting) + `docs/manual/cheatsheet.txt` (terminal-
  ready) + `docs/manual/elsereno-manual.docx` (pandoc-rendered
  with TOC). Plus `AUTHORS` + `TODO-vNext.md` (operator-
  requested forward-looking TODO with PBX discovery called
  out).
- **`scripts/dev-db.sh`** helper: up / down / reset / status /
  env verbs; writes `~/.elsereno/dev-db.env` (0600) with the
  DATABASE_URL export line.

### Changed

- **SLSA L3 provenance** now minted via GitHub's native
  `actions/attest-build-provenance@v2` (SLSA v1.0 predicate,
  Sigstore keyless, transparency log). Replaces
  `slsa-framework/slsa-github-generator` reusable workflow
  (exit-27 bug in v2.0.0 + v2.1.0, never fixed upstream).
  Verify with `gh attestation verify <artifact> --repo` or
  `cosign verify-attestation --type slsaprovenance1 …`.
- `handlers.APIV1()` now takes an `APIV1Deps{Broadcaster,
  Querier}` bundle. Missing deps downgrade individual
  endpoints to 503 without breaking the router.
- `.claude/settings.json` permissions allowlist expanded by
  35 patterns (docker compose / buildx, cosign verify-only,
  goreleaser snapshot, git tag -s, curl with safe flags).

### Removed

- **`-tags sqlite` portable variant** retired. Dockerfile.sqlite
  deleted; goreleaser `elsereno-sqlite` build gone;
  Makefile `build-sqlite` + `docker-sqlite` targets gone;
  CI `build-sqlite` job gone; `.golangci.yml` sqlite
  build-tag gone. Postgres is the only supported backend
  from v1.2. Operators running SQLite: see the migration
  path at the top of ADR-012 (now `superseded`).

### Fixed

- HART-IP handler now correctly distinguishes long- vs short-
  frame delimiters via the HIGH bit (0x80) per HART-FSK
  §9.1.2 — a low-nibble interpretation in the initial draft
  was wrong.
- ATModem read path no longer loses read-ahead bytes between
  phases (shared bufio.Reader cached on the struct).
- ATModem dialTimeout is now authoritative — `readUntilResult`
  runs the read in a goroutine + selects on ctx.Done so a
  stream without deadlines (net.Pipe) still honours the
  timeout.

## [1.1.0] — 2026-04-21

### Added — new features

- **Per-plugin offensive `WriteGatedHandler`** (ADR-040 close).
  `offensive/write/<proto>/gatedproxy.go` for modbus / s7 / enip
  with full wire-level Handle and protocol-native refusal frames
  (IllegalFunction, S7 AckData err-class 0x85, ENIP encapsulation
  status 0x0001). Session primitives (`AllowlistHash` +
  `SessionMutation`) for bacnet / dnp3 / iec104 / hartip / atg /
  fox; full Handle loops for those six ship in v1.2.
- **File-backed audit writer** at `~/.elsereno/audit.jsonl`
  (mode 0600, parent dir 0700). Chain-resumable across process
  restarts; `audit.VerifyFile` walks the chain end-to-end.
  `offensive/confirm/adapter.go` maps `confirm.AuditEvent` to
  `audit.Entry` without a schema migration.
- **Offensive CLI network delivery**: `elsereno write modbus
  send`, `elsereno exploit run`, `elsereno audit verify-file`
  tied together by `cmd/elsereno/offensive_runtime.go` (vault +
  writer + actor helper).
- **Server-Sent Events** at `GET /api/v1/stream`: process-local
  `internal/web/stream.Broadcaster` with channel-per-subscriber
  fan-out, `audit.FileWriter.SetObserver` hook, and
  `stream.TailAudit` cross-process file tailer so offensive
  verbs running in separate processes light up the dashboard.
  The dashboard inline template now carries a live-feed panel
  (EventSource, CSP-nonce whitelisted).
- **GHCR docker image** via goreleaser's `dockers_v2` block —
  multi-arch (linux/amd64 + linux/arm64) at
  `ghcr.io/robinr00t/elsereno:<tag>` + `:latest`, with
  `sbom: true` (CycloneDX) + `--attest=type=provenance,mode=max`
  attestations and cosign-keyless manifest signatures.
  `docker/setup-buildx-action@v3` + `docker/setup-qemu-action@v3`
  added to `release.yml` so the multi-arch + attestation
  pipeline works end-to-end.
- **Seccomp-bpf sandbox** for offensive subprocesses
  (ADR-042). `offensive/sandbox/bpf_linux.go` compiles
  per-profile denylist BPF programs; `installFilter` installs
  via `seccomp(SECCOMP_SET_MODE_FILTER, TSYNC)` so every
  goroutine-backing thread is covered. Profiles: `exploit`
  (base blocklist), `harvest` (+ file mutators), `dial` (+
  network openers). Wired into `write modbus send`,
  `exploit run`, `harvest *`, and `dial batch`. Integration
  tests fork a child and verify ptrace + socket return EPERM
  on native Linux.
- **OPC UA plugin** on port 4840. `internal/protocols/opcua/
  wire/` parses UA-TCP Part 6 §7.1 Hello/Acknowledge/Error
  frames; the probe classifies ACK / ERR / non-UA bytes.
  Default `ProxyHandler` refuses with a UA-native ERR frame
  (Bad_ResourceLimitsExceeded + "denied"). Write-gating
  (SecureChannel + Session + Write service) deferred to v1.2.
- **Wardialing batch** via `elsereno dial batch --numbers-file
  <path> --scope <scope.yaml>` — reads one number per line,
  classifies each against the ADR-041 dial guard, and appends
  one `offensive_dial` audit entry per decision. The seccomp
  `dial` profile is installed before classification. Default
  disposition is "preview" (audit-only dry-run); actual modem /
  VoIP delivery is a v1.2 carry-over.

### Changed

- `Dockerfile` + `Dockerfile.sqlite` pin Go 1.25.4 to match
  `go.mod`'s `go 1.25.0` requirement (previous 1.23.4 pin no
  longer passed `go mod download`).
- `elsereno dial` is now an umbrella verb with `validate`
  (single-number check, former top-level body) and `batch`
  (wardialing batch) subcommands.
- Dashboard auto-refresh interval extended from 30 s → 120 s
  because the SSE live feed replaces the need for frequent
  full-page reloads.

### Fixed

- CSP nonce is now threaded through request context via
  `internal/web/httpctx`; the dashboard's inline `<script>` and
  `<style>` tags carry matching `nonce` attributes. Inline
  styles were previously blocked by the Content-Security-Policy
  in most browsers (silent degradation to unstyled output).
- Legacy top-level `migrations/` directory removed; the
  `internal/db/migrations/` embed used by goose is the single
  source of truth. The audit-events-vs-SQL sync test walks
  every migration in order.

## [1.0.1] — 2026-04-21

### Fixed — release surface polish
- **cosign bundle**: goreleaser's `signs:` block now passes
  `--bundle=${artifact}.bundle` so the release publishes
  `checksums.txt.bundle` alongside the raw `checksums.txt.sig`.
  Consumers can run `cosign verify-blob --bundle checksums.txt.bundle
  …` without fetching the signing cert out-of-band.
- **SLSA provenance**: bumped `slsa-github-generator` from
  `v2.0.0` → `v2.1.0`. The v2.0.0 finaliser emitted exit 27
  (`SUCCESS=false`) even on a successful upload path, which is
  why v1.0.0 shipped without `.intoto.jsonl` assets. v2.1.0
  (2025-02-24) fixes the false-negative.
- **Pandoc pin**: release workflow installs pandoc 3.9.1 from
  the upstream `.deb` (was distro apt-get). Deterministic man-
  page output removes the reason we had to strip the strict
  "verify man pages in sync" step in the workflow.

### Changed — README
- Badge row (semver release, MIT licence, Go 1.25+, CI status,
  supply-chain status, SLSA 3).
- "Quick install (signed release)" section with the curl +
  shasum -c recipe + optional cosign bundle verification.
- Non-interactive vault-unlock snippet using
  `--vault-passphrase-file` pointing at ADR-026.

## [1.0.0] — 2026-04-20

### Added — F0 Scaffolding (closed 2026-04-19)
- Hexagonal Go 1.23 skeleton: `internal/core`, `internal/config`,
  `internal/exec` with `SafeCommand` + `CommandSpec`, `internal/audit`
  (placeholder chain), `internal/db` (goose migrations embed),
  `internal/render.SafeBytes`.
- Full `.context/` tree: 36 PITFs, 26 ADRs, templates, canonical
  docs, snapshots scaffolding.
- CI pipeline (lint + build ×3 + race/cover + fuzz smoke + sec +
  context-check), Makefile, Dockerfile + Dockerfile.sqlite,
  docker-compose.dev.yml, `.goreleaser.yml`, scripts, man sources.
- Root docs: `README.md`, `SECURITY.md`, `LEGAL.md`, `CONTRIBUTING.md`,
  `CODE_OF_CONDUCT.md`, `NON-GOALS.md`, `TODO.md`, `CLAUDE.md`.

### Added — F1 Inputs/scanner/scoring/triage/observability (closed 2026-04-19)
- Cobra CLI with `version/doctor/legal/plugins/config/scoring/vault/
  creds/db/audit/serve/scan/explain/why/triage/lint/fmt`.
- Koanf loader with unknown-field rejection (`ErrUnknownConfigField`).
- Zerolog with redaction hook (specific patterns + entropy >4.5 b/B +
  UUID v1–v5 exemption, PITF-004).
- Prometheus with low-cardinality label sanitiser (ASN numeric,
  country ISO 3166-1).
- pgx pool with ADR-021 TLS policy; goose migration runner via
  `pgx/v5/stdlib.OpenDBFromPool`.
- Real JCS audit canonicaliser (RFC 8785 via `gowebpki/jcs`).
- Encrypted vault at `~/.elsereno/vault.v1.bin` (AES-GCM +
  Argon2id + HKDF + memguard). CSRF key derived via HKDF from the
  vault master key.
- Scanner: A+AAAA+IDN resolve, dedupe, concurrent probes with global
  + per-host semaphores, token-bucket rate limiting, exponential
  backoff + jitter retries, circuit breaker, 5-minute temporal
  dedupe.
- Triage grouping (quick-win / strategic / routine).
- Outputs: NDJSON (schema `ndjson:v1`), CSV (`csv:v1`), HTML
  (`html:v1`).
- Shodan + Censys HTTP clients.
- Progress bars honouring `NO_COLOR`.
- Outbox worker with dead-letter after `max_attempts`.
- Retention with keep-if-referenced rule encoded in the Pruner
  interface.
- Web server scaffold (full timeouts, security headers, CSP nonces,
  `/healthz`, `/readyz`, CSRF via HKDF).
- banner plugin (first real Protocol).
- Integration test scaffold at `test/integration/` +
  `simulators/docker-compose.test.yml`.

### Added — F2 Legacy telephony (closed 2026-04-19)
- XOT (RFC 1613) plugin + simulator. TPKT/X.25 wire parser with 3
  fuzz targets (ADR-027).
- AT-modem plugin (Hayes / GSM / EN 81-28) + simulator. Line-
  oriented state machine with 64 KiB ceiling and `+CME/+CMS`
  error-code extraction. Vendor dictionary for Siemens, Nokia,
  Sierra, MultiTech, Cinterion, Telit, u-blox, Quectel, Huawei,
  KONE, Otis, Schindler. Proxy blocks ATD*, ATA, AT+CMGS, AT+CMGW,
  AT+CMSS, AT+CMGD, AT+CFUN, AT+CPWROFF, `+++` (ADR-028).
- Milestone: repo pushable to private GitHub.

### Added — F3 Proxy + Modbus (closed 2026-04-19)
- `internal/proxy`: generic TCP framework with Accept + Dial +
  per-connection idle deadline + symmetric Hook interface
  (PreHook with rewrite + PostHook observer). `LoggingHook` routes
  through `render.SafeBytes` (ADR-029).
- Modbus/TCP plugin (ADR-030): from-scratch MBAP + PDU parser,
  FC classifier (read / write / diagnostic / MEI / unknown),
  exception helper, FC 43/14 Device ID decoder, 3 fuzz targets.
  Probe sends FC 1 Read Coils + opportunistic FC 43/14. Proxy
  enforces the write-ban at the wire layer: every CategoryWrite
  FC, non-14 MEI sub-code, or Unknown FC is replied with
  IllegalFunction without touching upstream.
- `simulators/modbus/` (Go) for deterministic CI + pymodbus pointer
  for operator-driven richer scenarios.
- Chaos helpers under `test/chaos/` (`-tags chaos`):
  RandomDropReader, LatencyReader, FlipBitsWriter, EarlyCloser.
- Integration test exercising the proxy framework end-to-end.

### Added — F4 ICS plugins + dashboard + API (closed 2026-04-19)
- Eight new plugins, all with from-scratch wire parsers + probe +
  fuzz + ADR + protocol doc:
  `s7` (TPKT/COTP, 102), `enip` (EtherNet/IP CIP ListIdentity,
  44818), `bacnet` (BVLC Who-Is, UDP/47808), `dnp3` (IEEE 1815
  link frame, 20000), `iec104` (APCI TESTFR, 2404), `hartip`
  (session initiate, 5094), `fox` (Niagara Fox banner, 1911/4911),
  `atg` (Veeder-Root I20100, 10001). 12 plugins registered in the
  default build.
- `banner.DetectVendor()` with Moxa / Lantronix / Digi / NetBurner
  / KONE / Otis / Schindler / OpenSSH rules.
- Dashboard MVP at `/` (inline HTMX-ready HTML listing plugins);
  read-only API at `/api/v1/{plugins,scoring,health}` with envelope
  `{"schema":"api:v1","data":…}`.
- OpenAPI 3.1 spec at `docs/openapi.yaml`.
- Conpot honeypot added to `simulators/docker-compose.test.yml`
  with port maps for all new protocols.
- ADR-031..038.
- Fuzz-found panic in ENIP ListIdentity parser (truncated body)
  fixed with tighter bounds + corpus regression guard.

### Added — F5 Offensive build (closed 2026-04-19)
- ADR-039 triple-confirm wrapper (build tag + `--accept-writes` +
  `--confirm-target` + HMAC-SHA256 token derived via HKDF from the
  vault master key). Every Authorize call emits an audit event —
  allowed, denied, or failed — with payload hash but never the
  plaintext payload.
- ADR-040 per-plugin proxy write-gating. Every TCP-based plugin
  now refuses non-read frames at the wire layer in the default
  build with a protocol-native refusal response (S7 AckData
  err-class 0x85, ENIP status 0x0001, DNP3 FC 15 "Not Supported",
  IEC-104 STOPDT_act, HART-IP session-close status 0x04, ATG
  `9999FF1B` Data-Error). Fox is fail-closed; BACnet (UDP) errors
  immediately under the TCP proxy framework.
- ADR-041 dial guard. Unbypassable ≤3-digit hard block, plus
  scope.yaml `blocked_numbers` prefix/exact match. Wardialing
  batch stays vNext.
- ADR-042 Linux seccomp-bpf sandbox scaffold via pure-Go
  `golang.org/x/sys/unix.Prctl` (`PR_SET_NO_NEW_PRIVS`); BPF
  filter sequences land with F6 subprocess integrations.
- `offensive/write/{modbus,s7,enip,bacnet}` — write plugins with
  deterministic SHA-256 payload hashes. Modbus FC 5/6/15/16; S7
  WriteVar / PLC Stop / PLC Restart; ENIP Set Attribute Single /
  Reset; BACnet WriteProperty (UDP BVLC).
- `offensive/dial/Validate` — three-gate validator (normalise →
  hard ≤3-digit → scope blocked-numbers).
- `offensive/harvest` — Prober interface + four implementations:
  telnet (IAC negotiation + login state machine), ftp (RFC 959),
  http-basic (RFC 7617 with challenge-first), snmp (SNMPv2c
  GetRequest for sysDescr.0 with hand-crafted ASN.1 BER).
- `offensive/exploits` — registry-based harness + two public,
  stable DoS modules: **CVE-2015-5374** (Siemens SIPROTEC 4 /
  Compact EN100 UDP DoS) and **CVE-2019-10953** (Schneider /
  Allen-Bradley / Phoenix Contact CIP ListIdentity DoS).
- `internal/canary` — Sender interface + HTTP sender that POSTs
  `canary:v1` JSON envelopes with optional HMAC-SHA256 signature.
- `internal/scope.(*Scope).CheckDial` — scope side of the dial
  guard.
- `internal/exec.CommandSpec.AllowAnyPath` + `BypassAuditor` —
  `--no-allowlist` escape hatch; refuses to spawn when the
  audit auditor is missing or errors.

### Added — F6 Reporting + release (closed 2026-04-20)
- Five new output sinks: CEF 0.1 (ArcSight; 1..10 severity,
  sorted extensions), RFC 5424 syslog (facility local1 with
  `elsereno@32473` SD-ID), JIRA Cloud REST v3 (ADF description,
  severity→priority mapping), GitHub Issues REST (Bearer PAT +
  2022-11-28 API pin + markdown factor table), and a generic
  HMAC-SHA256-signed webhook.
- HTML report polish: dark-mode palette, per-protocol sections
  with count / max / avg, top-5 factor histogram, severity chips
  with level-specific colours.
- OpenAPI 3.1 autogenerada: `internal/web/openapi.Spec()` is the
  single source of truth; `GET /api/v1/openapi.yaml` serves it
  live; `elsereno api openapi [-o <path>]` refreshes the on-disk
  snapshot.
- Offensive CLI verbs behind `-tags offensive`:
  `elsereno write modbus` (dry-run PDU + payload hash),
  `elsereno exploit list|show|dry-run`,
  `elsereno harvest {telnet,ftp,http-basic,snmp}`,
  `elsereno dial --number <E.164>` with the three-gate
  validator in isolation. Default build unchanged (stub).
- `--vault-passphrase-file <0600 path>` on `vault init`,
  `vault unlock`, `serve`. `os.Lstat` rejects symlinks / pipes /
  devices; mode `perm &^ 0o600 != 0` rejects lax permissions;
  empty-file rejection; CRLF stripping. ADR-026 / PITF-016.
- Operator docs at `docs/protocols/` (12 per-plugin pages +
  README) covering probe bytes, proxy default policy, writes
  behind offensive build, scope + impact, public references.
- Dashboard polish (`/`): dark-mode, plugin grouping (default
  vs offensive), scoring sidebar (ADR-006 weights + severity
  thresholds), auto-refresh pending SSE.
- `RELEASING.md` operator runbook: goreleaser v2 dry-run
  recipe, SBOM via syft (CycloneDX 1.6), cosign keyless
  Sigstore signing + receiver verification, tagging /
  rollback.
- `.goreleaser.yml` migrated `archives.builds` →
  `archives.ids` (goreleaser v2).

### Added — F7 Hardening + 1.0 (closed 2026-04-20)
- Dockers_v2 migration (final goreleaser v2 deprecation cleared)
  + nightly per-target fuzz matrix (30 min per `Fuzz*` target)
  with artefact-uploaded corpora.
- Regression benchmarks: `benchmarks/baseline.txt` checked in;
  benchstat CI comments on every PR with the delta vs base;
  strict mode turns ≥ 10 % regressions into failures.
- OpenTelemetry tracing scaffolding: env-driven exporter
  (`none`/`stdout`/`otlp`), scanner retry/attempt loop emits
  spans with target/port/attempt/plugin attributes.
- 6 STRIDE threat-model docs under `.context/threat-model/`
  (vault-audit, web, scanner-proxy, exec-scope, offensive,
  telemetry-canary) with per-surface residual-risk policy.
- Supply-chain automation at `.github/workflows/supply-chain.
  yml`: OpenSSF Scorecard nightly, SLSA L3 provenance verify
  on tag, dependency-review with licence deny-list (GPL/AGPL/
  LGPL/SSPL/Commons-Clause/Elastic-2.0), osv-scanner,
  licenses-audit artefact.
- `internal/backup`: AES-256-GCM envelope (magic + version +
  salt + nonce + ciphertext) with two-stage HKDF key
  derivation. Salt bound into AEAD AAD so salt-swap attacks
  fail closed. 10 unit tests cover every tamper mode.
- `elsereno backup {create,restore,inspect}` CLI verbs
  honouring `--vault-passphrase-file` for non-interactive
  startup.
- Pentest dashboard panel at `/admin/security`: 11 in-process
  controls with status pills, code-path + ADR references, and
  links to all 6 threat-model docs + every external sec-suite
  job.
- `scripts/release-gate.sh` + `make release-gate`: 11 local
  checks (tests, lint, context, docs, goreleaser snapshot,
  sec-suite, benchmarks baseline) gate the v1.0 tag locally.
- `RELEASING.md` 1.0 section + new `SUPPLY-CHAIN.md` root doc
  with SLSA mapping + dep policy + SBOM diff recipe +
  secrets-rotation table.

### Current phase
**v1.0.0 signed release** is the next milestone (operator
task; `make release-gate` must be green on a clean tree).
See `.context/STATE.md` for authoritative live state,
`.context/snapshots/f7-hardening-1.0.md` for the last
retrospective.
