---
phase: v2.63-closed; vNext items (OPC UA HTTPS write, GOOSE/SV, CI) 2026-09-23
status: tags published through v2.62; CI green on main
last-updated: 2026-10-03
token-budget: 320
---

# Current state

**2026-09-28/30 OT-exposure probes** (from chrisdinozzi/opcua-recon;
read-only). Signed on main: Modbus monitor, MQTT/Sparkplug, OPC UA
anon-access (`opcua probe-anon`) + writeable walk (`opcua probe-write`,
spec-grounded), S7 protection/identity/posture (`s7 probe`,
`probe-protection`, `probe-identity`) + `--json` on all probes. S7 validated
BYTE FOR BYTE vs real pcap s7comm_reading_plc_status. Opt-in scored-Finding
plugins, read-only + signed: `s7-exposure` (ProbePosture) + `opcua-exposure`
(anon + writeable walk). Opt-in enforced by `core.PluginMetadata.OptIn`
(resolvePlugins skips OptIn, plus DefaultPort 0): neither the CLI sweep nor a
scanorch run-everything job runs them. PITF-031/063: audit pins golangci
v2.11.4, ci latest (v2.14.0); diverge BOTH ways, lint with both before push.

**2026-10-02/03 capture validation + proprietary-probe audit**: FOUR fixture/model
bugs, all fixed: Modbus FC43/14 (PITF-064); Omron FINS SystemVersion (PITF-065);
GE-SRTP init (sent 0x02/exp 0x03 = operation; real = 56 zeros -> 0x01, PITF-067);
ProConOS (sent 01060010 PROCONOS; real query cc01000b... -> 0xcc sig, PITF-069).
CoDeSys magic 0xCDCDCDCD wrong (real 0xE8170100, now capture-confirmed on TCP/11740 via cds3.pcapng); deferred, still no host-independent probe frame (PITF-068). IAX2 full-frame header + NEW validated vs a real capture (Wireshark IAX2_incoming_call), no bug. TwinCAT ADS ReadDeviceInfo + XOT/X.25 cross-checked vs spec (TwinCAT: fixed a stale doc comment, name is 16B not 24B); CWMP/AT-modem/Red Lion classified -> validation sweep COMPLETE. NIST Table 16: weak-TLS posture added to plaintext-check (confirms deprecated TLS 1.0/1.1 acceptance + expired cert; aae1560). Coverage raised: atg 2.6->79.5%, fox 4.8->97.6%, bacnet/twincat plugin 0->45/56% (100c7cf). GOOSE (IEC 61850-8-1) validated vs a real GE F650 capture (w3h/icsmaster GOOSE.pcap) byte-for-byte, no bug; was fixture-only and not in the matrix. SV path still fixture-only. PROFINET DCP Identify response validated vs a real capture (w3h/icsmaster ChangeIPUsingDCP.pcap, station X208-BORD), no bug; also was fixture-only and not in the matrix.

**2026-10-03 CVE enrichment** (increments 1-4) + repo em-dash cleanup (4b09ca6,
740 files, 0 dashes): `internal/cve` maps a family to curated REAL web-verified
CVEs. S7 MLFB; ENIP 1756-EN2x -> CVE-2025-7353; PC WORX ProConOS; FINS Omron by
model (NJ/NX -> CVE-2022-31206 9.8; CJ/CS/CP -> CVE-2019-18269/45790). Fixed wrong CVEs in enip/pcworx/finsudp comments. Baseline-comment audit (PITF-070): SIX fabricated ids purged (knxip/slmp/dlms/gesrtp/mbustcp + pbxhttp CVE-2020-25822, NVD totalResults=0); the 13 suspected comments verified id-by-id vs NVD REST API; mis-attributions de-specified (iec104/bacnet/opcua/sip/fox/iax2/atg/hartip/twincat), only s7/dnp3/cwmp clean at source.

**2026-10-01/02 standards traceability** (SP 800-82 r4 IPD): all output
surfaces except CSV (stable csv:v1 contract), keyed by protocol
(`internal/standards`), core.Finding untouched. ndjson + `standards` catalog
(3b74a67) + HTML (72334aa) + GitHub/Jira (106c96d) SIGNED; CEF/syslog
(`standards.Summarise`) + STIX external_references + webhook unsigned.

**2026-09-23/28 vNext items** (landed on main, signed, CI green):
- **CI:** `ci-passed` aggregator collapses the 10 ci.yml checks into one
  required check (branch protection -> `[ci-passed, audit]`, robust to
  job renames). PITF-061/062/063 capture the audit lessons.
- **OPC UA HTTPS write-gate** (`-tags offensive`): the §7.4 binary
  binding (bare UA-Binary POST body). Reuses the opc.tcp parsers via a
  16-byte splice (`wire.ServiceTypeIDHTTPS`). `write opcuahttps` +
  `proxy --plugin opcuahttps`; transport-scoped token. PITF-060.
- **IEC 61850 GOOSE/SV passive monitor** (default build): `goose decode`
  + `goose monitor` (offline `--file` AND live `--iface`, Linux
  AF_PACKET) flags stNum jump/regression, test bit, ndsCom, confRev, SV
  smpCnt. `internal/protocols/goose`.

**2026-08-31 maintenance session** (no version bump; `main` CI-green):
- **CI/CD reactivated.** ci / release / supply-chain / nightly /
  benchmarks are no longer `workflow_dispatch`-only. The 2026-04 disable
  was the org `allowed_actions=local_only` policy (fixed 2026-08-29), not
  Actions billing. All workflows green on `main`.
- **v2.38 → v2.62 tags pushed** (25 signed tags; remote was stuck at
  v2.37). Binary releases still follow the local-goreleaser flow.
- **Reliability fixes (signed):** `audit.sh` skips its CI local-sync
  check; `TestStream_ClientCancelReleasesSubscription` de-flaked;
  idempotency tests isolate the process-global cache. See pitfalls.md.

**Phase**: **v2.63 cycle closed on `main`** (1 chunk +
close). `elsereno sandbox diff PROFILE_A PROFILE_B`
subverb, line-level symmetric difference of two profile
.sb Schemes (the vNext follow-up flagged in the v2.62
snapshot). Text-unified (`+`/`-` prefixes) or `--json`
(`a`/`b`/`only_in_a`/`only_in_b`/`common`, all sorted).
Needs darwin+cgo schemes; other offensive builds error
with "schemes unavailable". +4 tests on both build paths.
INSTALL.md matrix row updated.
Snapshot: `.context/snapshots/v2.63.0-sandbox-diff-verb.md`.

**v2.62 cycle (closed)**: `elsereno sandbox` CLI verb (list
+ introspect) surfaces the v2.61 `SchemeFor()` accessor.
Platform split: darwin+cgo emits real .sb Schemes; other
offensive builds emit sentinel `{"scheme": ""}` rows for
stable JSON shape. +7 tests on both build paths.
Snapshot: `.context/snapshots/v2.62.0-sandbox-cli-verb.md`.

**v2.61 cycle (closed)**: sandbox profile introspection; `Profiles()` +
`SchemeFor()` (darwin+cgo) accessors; hardened sandbox_init errbuf path.

**v2.60 cycle (closed)**: /metrics endpoint + pool collector wiring
(buildMetricsHandler registers the v2.55 PoolCollector). +2 tests.

**v2.57-v2.38 cycles (closed)**: OIDC Verifier + PoolStat wiring,
OpenAPI examples, PROFINET DCP codec + CLI, per-route OIDC, OIDC +
roles auth package.

**v2.37 cycle (closed)**: Wardialing batch orchestrator
(range + workers + rate-limit + checkpoint).

**v2.35 + v2.36 cycles (closed)**: v2.35 OPC UA HTTPS
fingerprint plugin. v2.36 MMS vendor hint + LD
enumeration.

**v2.34 cycle (closed)**: Windows cross-compile target.

**v2.13-v2.25 cycles (closed)**: sparkline + clones +
ETag plumbing + bulk tag-rename + NOT operator +
Idempotency-Key + multi-select chips + ?atomic=tx +
real PG WithTx + sparkline tooltips + recursive
clone-chain + localStorage ETag cache +
idempotency-on-clone-bulk.

**v2.6-v2.12 cycles (closed)**:
v2.6 dashboard tag UI. v2.7 ETag. v2.8 CLI mutating
verbs. v2.9 multi-tag AND/OR. v2.10 source_schedule_id
provenance (00017). v2.11 time-bucketed stats. v2.12
atomic import preflight.

**v1.89-v2.5 cycles (closed; per-cycle snapshots)**:
v1.89 deleted badge + per-schedule retention (00013).
v1.90 advisory-locked pruner. v1.91 pruner counters.
v1.92 schedule run history (00014). v1.93 clone. v1.94
pruner tick histogram. v1.95 bulk pause/resume. v1.96
OpenAPI coverage. v1.97 export. v1.98 OpenAPI strict
schemas. v1.99 import. v2.0 cursor pagination
(BREAKING). v2.1 cloned_from audit event (00015).
v2.2 run-stats aggregate. v2.3 schedule CLI verbs.
v2.4 tags + GIN index (00016). v2.5 tag-counts.

**v1.73 → v1.89 cycles** (closed; per-cycle snapshots in
`.context/snapshots/v1.<N>.0-*.md`): schedule domain
build-out from cron expressions through audit retention.
Highlights: v1.73 cron parser + 00008 XOR check, v1.74
edit, v1.75 timezone (00009), v1.76 @daily shortcuts, v1.77
next-fire preview, v1.78 optimistic locking (00010), v1.79
multi-fire preview, v1.80 debounced preview, v1.81 412
merge-view, v1.82 AbortController, v1.83 cherry-pick merge,
v1.84 force-overwrite audit (00011), v1.85 audit-history
UI, v1.86 PruneOlderThan, v1.87 background pruner, v1.88
expanded audit event types (00012), v1.89 deleted badge +
per-schedule retention (00013) + `scripts/audit.sh` +
`.github/workflows/audit.yml`.

**v1.72 cycle (closed, snapshot available)**:
Dashboard "Scheduled scans" panel. 1 chunk + close:
`c3a70b1`, `990dcd3`. Snapshot:
`.context/snapshots/v1.72.0-schedule-ui.md`.

**v1.69 cycle (closed, snapshot available)**:
Bulk scan-submit endpoint + dashboard textarea panel.
1 chunk + close: `2d5906c`, `3d762a2`. Snapshot:
`.context/snapshots/v1.69.0-bulk-submit.md`.

**v1.68 cycle (closed, snapshot available)**:
Plugin-list autocomplete UI (native <datalist>).
1 chunk + close: `da38143`, `92a601d`. Snapshot:
`.context/snapshots/v1.68.0-plugin-autocomplete.md`.

**v1.67 cycle (closed, snapshot available)**:
DBStore persistence for findings_by_plugin
(migration 00006). 1 chunk + close: `bd804e7`,
`0d06755`. Snapshot:
`.context/snapshots/v1.67.0-findings-by-plugin-db.md`.

**Pre-existing govulncheck failures**: stdlib
vulndb picked up GO-2026-4971 + GO-2026-4918 on
go1.26.2 (fixed in 1.26.3). Pre-existing code
paths only; v1.68 / v1.69 introduce no new
vulnerable callsites. Operator upgrades Go
toolchain in CI/build.

**v1.65 + v1.66 cycles (closed, snapshots available)**:
scan_stats_progress SSE (v1.65) + per-plugin findings
breakdown (v1.66). Snapshots in `.context/snapshots/`.

**v1.58 → v1.65 cycles** (closed; per-cycle snapshots
in `.context/snapshots/`):
dashboard scan-orchestration feature line, 
v1.58 shell + v1.59 worker + v1.60 DB store +
v1.61 runner + v1.62 panel + v1.63 state-SSE +
v1.64 multi-plugin + v1.65 progress-SSE.

**v1.50 → v1.58 cycles** (closed; per-cycle snapshots in
`.context/snapshots/`): macOS sandbox_init(3) (v1.50),
MMS/IEC 61850 IED ID (v1.51), s7 + enip per-object gating
(v1.52/v1.53), TwinCAT ADS fingerprint (v1.54), KNX + M-Bus
+ DLMS write-gated proxies (v1.55-v1.57), dashboard scan-
orchestration shell (v1.58). v1.59+ is forward progress on
dashboard orchestration.

**v1.41 → v1.49 cycles (closed; per-cycle snapshots in
`.context/snapshots/`):**
record/replay forensics + Linux packaging, tui --record
(v1.41), replay round-trip (v1.42), tui --rate (v1.43),
proxy replay --since/--until (v1.44), --json (v1.45),
--limit (v1.46), --tail (v1.47), --stats (v1.48). Linux
deb/rpm/apk via nfpm + hardened systemd units (v1.49).

**v1.32 → v1.40 cycles (closed; per-cycle snapshots in
`.context/snapshots/`):**
hygiene + tooling cycles, gosec marker migration (v1.32
+ v1.34), teatest TUI integration (v1.33), proxy listen
for 4 legacy-ICS protocols + recording (v1.35), dashboard
--input preview endpoint (v1.36), fingerprint
validate/capture verbs (v1.37 + v1.38), discover --hosts
(v1.39), plugins ports reverse-index (v1.40).

**v1.28 → v1.31** (closed; snapshots): ProConOS fingerprint, TUI verb +
mini build, record-replay across 9 gates + proxy listen/replay, TUI --input.

**v1.0 → v1.88 published** on github.com/RobinR00T/elSereno/releases
(`v1.88.0`, 2026-05-11, 35 assets via goreleaser).

GitHub Actions: all workflows live since 2026-08-31 (ci, audit,
codeql, supply-chain, nightly, benchmarks, release,
auto-approve-dependabot). The 2026-04 `workflow_dispatch`-only
gating was the org `allowed_actions=local_only` policy (fixed
2026-08-29), not billing. `release.yml` runs a real goreleaser
release on tag push and a `--snapshot` on dispatch; nightly runs
30-min deep fuzz. Local goreleaser + syft + `gh release upload`
remains an option since v1.8.

**Counts now** (authoritative: `elsereno plugins list`):
- **30 protocol plugins** (default build); adds opcuahttps, proconos,
  twincat, atg/atmodem/dlms/dnp3/hartip/iec104/knxip/mbustcp/mms over
  the old 25-list. (profinet is CLI decode-only, not a probe plugin.)
- 24 offensive write-gated proxies (`-tags offensive`). GE-SRTP,
  CoDeSys and Red Lion landed 2026-09-01 on validated public
  dissectors; finsudp (UDP/9600), slmp (TCP/5007) + a UDP transport
  (Options.Network) landed 2026-08-31. Refusal: FINS/SLMP native error;
  GE-SRTP/CoDeSys/Red Lion close-on-refuse; OPC UA ServiceFault. Each
  ships `write <p> [proxy-]dry-run` token minting + a simulator demo
  (scripts/demo-*-proxy.sh, 8 of them). CoDeSys is a fail-closed L7
  magic-scan (no trustworthy L3/L4 length).
- **Modbus FC 8 Diagnostics sub-function gate (2026-09-03):** reads
  forward; mutating (Force Listen Only 0x04 DoS, Clear Counters 0x0A,
  ...) default-deny unless `--diag-subfunction` (token-bound, compat-
  preserving). Closes the "permissive FC 8" gap. PITF-058.
- **DNP3 write-gate wired + deepened (2026-09-22):** CLI-reachable;
  gates app-FC + CROB (TRIP/CLOSE) + g41 analog (value-clamp) +
  broadcast deny + link pin, token-bound; + IIN monitor
  -> audit (dnp3_iin_alert, 00005) -> `audit export` CEF/syslog. PITF-059.
- **OPC UA HTTPS deep fingerprint**: `opcuahttps` (4843) POSTs a real
  GetEndpointsRequest + enumerates endpoints (SecurityMode=None raises
  exposure/auth_state). New verb `fingerprint probe --plugin P --target H:P`.
- 7 attack-surface input providers: shodan, censys, fofa,
  zoomeye, onyphe, binaryedge, internetdb.
**Deferred to v1.25+**:
- cve_exposure for finsudp / slmp / gesrtp / knxip / mbustcp /
  dlms once their CVE histories harden.
- IEC 61850 MMS; PROFINET-RT (L2) live capture; DNP3 SAv5 gating;
  PROFINET-RT live L2 capture (GOOSE/SV live capture done 28-9).

**Live services**: dashboard 127.0.0.1:8787; dev-db (pg 16)
127.0.0.1:5433 via `scripts/dev-db.sh`.
