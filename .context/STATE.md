---
phase: v1.82-closed
status: v1.16-v1.27 published; v1.28-v1.82 tags pending push
last-updated: 2026-05-10
token-budget: 320
---

# Current state

**Phase**: **v1.82 cycle closed on `main`** (1 chunk +
close). Dashboard-only JS: AbortController cancels
in-flight /preview requests when a newer debounced call
fires. Fixes the v1.80 stale-flash gap (debounce delayed
dispatch but didn't cancel in-flight). `typeof
AbortController` guard preserves pre-2018 browser
compatibility. 3 dashboard markers.

Snapshot: `.context/snapshots/v1.82.0-abort-controller.md`.

**v1.82 chunks landed (in-flight)**:
- 1 `8ffffb3` — previewAbortController + AbortError
  silent-skip + 3 dashboard markers.

**v1.81 cycle (closed, snapshot available)**:
412 merge-view UI (field-level diff + Take server /
Force overwrite buttons). 1 chunk + close: `ba6e721`,
`896aa6c`. Snapshot:
`.context/snapshots/v1.81.0-merge-view.md`.

**v1.80 cycle (closed, snapshot available)**:
Live preview on cadence-field change (350ms debounce).
1 chunk + close: `321b960`, `91d6634`. Snapshot:
`.context/snapshots/v1.80.0-live-preview.md`.

**v1.79 cycle (closed, snapshot available)**:
Multi-fire preview (next N fires). ScanSchedule.NextFires
+ PreviewNextFires + /preview ?count=N. 1 chunk + close:
`64ebb77`, `52c382b`. Snapshot:
`.context/snapshots/v1.79.0-multi-fire-preview.md`.

**v1.78 cycle (closed, snapshot available)**:
Optimistic locking on schedule edits (UpdatedAt +
If-Match → 412). Migration 00010 + DB conditional UPDATE.
1 chunk + close: `c31fedf`, `bbe6eb8`. Snapshot:
`.context/snapshots/v1.78.0-optimistic-locking.md`.

**v1.77 cycle (closed, snapshot available)**:
Dashboard next-fire preview (tz-aware). 1 chunk + close:
`21756ad`, `7e711b7`. Snapshot:
`.context/snapshots/v1.77.0-next-fire-preview.md`.

**v1.76 cycle (closed, snapshot available)**:
Named cron shortcuts (@daily/@hourly/etc.). 1 chunk +
close: `b7bd346`, `29d63fb`. Snapshot:
`.context/snapshots/v1.76.0-cron-shortcuts.md`.

**v1.75 cycle (closed, snapshot available)**:
Per-schedule timezone for cron expressions. cronIsDue
converts anchor + now to s.Timezone before computing
Next/Match. Migration 00009 + scheduleColumns 11 → 12.
1 chunk + close: `01011dd`, `ab89a32`. Snapshot:
`.context/snapshots/v1.75.0-schedule-timezone.md`.

**v1.74 cycle (closed, snapshot available)**:
Schedule edit path (Update + PUT /schedules/{id} +
dashboard edit-mode toggle). 1 chunk + close:
`e72fc73`, `3293769`. Snapshot:
`.context/snapshots/v1.74.0-schedule-edit.md`.

**v1.73 cycle (closed, snapshot available)**:
Cron expressions as alternative cadence (5-field
parser + migration 00008 cadence-XOR CHECK). 1 chunk
+ close: `50ad219`, `577ca14`. Snapshot:
`.context/snapshots/v1.73.0-cron-expressions.md`.

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

**v1.16 → v1.27 are published** on
https://github.com/RobinR00T/elSereno/releases. v1.28.0+ tags
pending push.

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
