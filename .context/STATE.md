---
phase: v2.36-closed
status: v1.16-v2.34 published; v2.35-v2.36 tags pending push
last-updated: 2026-05-16
token-budget: 320
---

# Current state

**Phase**: **v2.36 cycle closed on `main`** (1 chunk +
close). MMS vendor hint + LD enumeration. Extends the
v1.51 mms plugin past ACSE association: vendor-marker
extraction from AARE (19 curated names) + confirmed-
service GetServerDirectory request to enumerate Logical
Devices. Findings carry vendor-hint + LD list. Closes
deferred roadmap item #2 (grande).

Snapshot: `.context/snapshots/v2.36.0-mms-vendor-ld.md`.

**v2.35 cycle (closed)**: OPC UA HTTPS fingerprint
plugin (Part 6 binding on 4843). Default plugin count
25 → 26. Closes deferred roadmap item #3 (medio-grande).

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

**v1.66 cycle (closed, snapshot available)**:
Per-plugin findings breakdown. 1 chunk + close:
`f0255b5`, `5fe8388`. Snapshot:
`.context/snapshots/v1.66.0-findings-by-plugin.md`.

**v1.65 cycle (closed, snapshot available)**:
scan_stats_progress SSE event with per-job throttle.
1 chunk + close: `b7f8158`, `4fa625d`. Snapshot:
`.context/snapshots/v1.65.0-scan-stats-progress.md`.

**v1.58 → v1.65 cycles** (closed; per-cycle snapshots
in `.context/snapshots/`):
dashboard scan-orchestration feature line —
v1.58 shell + v1.59 worker + v1.60 DB store +
v1.61 runner + v1.62 panel + v1.63 state-SSE +
v1.64 multi-plugin + v1.65 progress-SSE.

**v1.50 → v1.58 cycles** (closed; per-cycle snapshots
in `.context/snapshots/`): macOS sandbox_init(3) cgo-
gated (v1.50), MMS ACSE A-ASSOCIATE-REQUEST for IEC
61850-8-1 IED ID (v1.51), s7 per-(area, db, byte-
address) gating (v1.52), enip per-(class, instance,
attribute) gating (v1.53), TwinCAT ADS fingerprint
plugin (v1.54), KNX offensive write-gated proxy
(v1.55), M-Bus over TCP offensive write-gated proxy
(v1.56), DLMS/COSEM offensive write-gated proxy
(v1.57), dashboard scan-orchestration shell (v1.58 —
closes v1.50 F). v1.50 substantial-items batch
(A=v1.52, B=v1.53, C=v1.54, D1=v1.55, D2=v1.56,
D3=v1.57, E=v1.51, F=v1.58) fully done; v1.59+ is
forward progress on dashboard orchestration.

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

**v1.28 → v1.31 cycles** (closed; per-cycle snapshots in
`.context/snapshots/v1.<N>.0-*.md`):
ProConOS fingerprint + record-replay POC (v1.28), TUI verb +
mini build (v1.29), record-replay wire-up across 9 gates +
proxy listen/replay + TUI scan launcher (v1.30), TUI --input
parity with batch scan (v1.31).

**v1.0 → v1.88 are published** on
https://github.com/RobinR00T/elSereno/releases (`v1.88.0`
shipped 2026-05-11 with 35 assets via goreleaser). v1.89 tag
pending push.

v1.12 → v1.27 closed loose ends (per-object scoping across
all 7 write-gates; BACnet/CWMP completion; IPv6 cross-cutting;
CVE-exposure factor across 7 plugins). See snapshots for
chunk-level detail. v1.15 was the last manually-counted asset
release (9 assets); v1.16+ ship via goreleaser.

GitHub Actions: `audit.yml` (push/PR + weekly Mondays 06:00
UTC) is the canonical live gate since v1.88. `ci.yml` +
`release.yml` + others gated to `workflow_dispatch` (billing
post-flip; reactivate via the `on:` stanza). Local
goreleaser + syft + `gh release upload` remains the release
path since v1.8.

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

**Operator-pending**:
- Push v1.89.0 tag + goreleaser release (post-session).
- Set Workflow permissions → write in repo Settings (release
  flow needs token write scope; audit detected).

**Live services**: dashboard 127.0.0.1:8787; dev-db (pg 16)
127.0.0.1:5433 via `scripts/dev-db.sh`.
