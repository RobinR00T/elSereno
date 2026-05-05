# ElSereno — Forward-looking TODO (vNext)

Complementa a `TODO.md` (la checklist original del brief — closed
tras v1.12.0) y a `ROADMAP.md` (el plan chunked). Aquí se apuntan
ideas de features futuras, superficies de ataque a añadir y
mejoras operativas que surgen en campo.

> Mantén este fichero **corto y accionable**. Cuando un ítem
> entre en un ciclo (v1.x) muévelo a `ROADMAP.md` con su chunk
> asignado + estimación. Cuando cierre, márkalo `✅` con la
> versión y/o el commit.

Last refresh: **2026-05-03** (post-v1.33). Items shipped during
v1.3 → v1.33 archived to keep this file actionable.

---

## ✅ Shipped during v1.3–v1.24

### v1.3 → v1.15 (PBX discovery + IPv6 + observability foundations)

- ✅ **PBX discovery (Asterisk / FreePBX / Cisco UCM / 3CX /
  Mitel / Avaya / Yeastar / Grandstream)** — v1.3 chunks 1-3 +
  v1.4 chunk 5. SIP / IAX2 / pbxhttp probes + 15 PBX vendor
  fingerprints.
- ✅ **TR-069 / CWMP probe + offensive proxy** — v1.4 chunk 5
  (probe) + v1.11 chunk 1 (gate) + v1.12 chunks 1, 10
  (per-parameter-path + per-firmware).
- ✅ **FOFA / ZoomEye / ONYPHE input clients** — v1.8 chunks 1-2
  + v1.9 chunk 4. CLI wire-up via `--input <provider>:<query>`
  + `--api-creds-file <yaml>` — v1.9 chunk 3.
- ✅ **Shodan InternetDB (no-key provider)** — v1.12 chunk 9.
- ✅ **Input pagination across 5 providers** — v1.12 chunk 8.
- ✅ **SLSA-pivot to free-tier** — v1.8.0+ ships GPG-signed tag
  + SHA-256 + CycloneDX SBOMs locally; cosign+SLSA+GHCR remain
  available behind GitHub Actions billing restore.
- ✅ **Per-object / per-path scoping across 7 write-gates** —
  v1.12 chunks 1, 2, 3, 4, 5, 6, 7, 10. SIP From-domain (chunk
  5), Modbus structured writes (chunk 4), OPC UA rich NodeIDs +
  CallMethod (chunks 3, 6), BACnet per-WriteProperty (chunk 7),
  CWMP per-parameter-path + per-firmware (chunks 1, 10).
- ✅ **InternetDB bulk lookup** — v1.13 chunk 1.
- ✅ **CWMP firmware pre-flight verifier** — v1.13 chunk 2.
- ✅ **BACnet per-object for WritePropertyMultiple (svc 16)** —
  v1.13 chunk 3.
- ✅ **CWMP RPC-name case-warning in dry-run** — v1.13 chunk 4.
- ✅ **CWMP-over-TLS operator recipe** — v1.13 chunk 5 (docs only).
- ✅ **Triage bucket "utility"** — v1.13 chunk 6 (4th bucket).
- ✅ **BACnet per-target / per-state / per-operation /
  per-instance / per-(object,property) scoping for the 7
  remaining mutating services** — v1.13 chunks 7-13.
- ✅ **IPv6 cross-cutting support** — v1.14 (4 chunks).
- ✅ **CWMP TransferComplete observer (parsing half)** —
  v1.15 chunk 1.
- ✅ **`elsereno discover --auto <CIDR>`** — v1.15 chunk 2.
- ✅ **STIX 2.1 export** — v1.15 chunk 3.
- ✅ **Audit chain cross-process merge via flock** — v1.15
  chunk 4.
- ✅ **SIGHUP reload of proxy listen allowlist (supervisor
  variant)** — v1.15 chunk 5.

### v1.16 → v1.18 (refinements + observability + dashboard UX)

- ✅ **CWMP TransferComplete authorisation cross-reference** —
  v1.16 chunk 1. Closes the v1.15 chunk-1 observer half:
  envelope is now correlated with prior Download authorisation
  (CommandKey ↔ allowlist firmware metadata).
- ✅ **BACnet per-(type, instance) CreateObject** — v1.16 chunk 2.
  Refines v1.13 chunk 8 from per-type → per-instance.
- ✅ **BACnet per-(operation, type, instance) LifeSafetyOperation
  scoping** — v1.16 chunk 3. Refines v1.13 chunk 11 from
  per-operation → per-target.
- ✅ **BACnet token-generation cookie** — v1.16 chunk 4.
  Foundation separator 0xF5.
- ✅ **Token-generation parity across 6 plugins** — v1.17
  chunks 1-3. CWMP / SIP / Modbus / IAX2 / pbxhttp / OPC UA
  cookie rollout. All 7 gates now share the same shape.
- ✅ **In-process allow-file reload (SIGUSR1 + atomic swap)** —
  v1.17 chunk 4. Supersedes the v1.15 chunk-5 supervisor pattern.
- ✅ **`proxy_allowlist_reload` audit event** — v1.17 chunk 5.
- ✅ **Dashboard: CSV export from Findings panel** — v1.18 chunk 1.
- ✅ **Dashboard: diff between two runs** — v1.18 chunk 2.

### v1.19 → v1.21 (observability completion + legacy ICS roll-out)

- ✅ **Audit log API endpoint + dashboard panel** — v1.19 chunk 1.
- ✅ **Reload cadence dashboard panel** — v1.19 chunk 2.
- ✅ **CWMP TransferComplete async firmware re-fetch** —
  v1.19 chunk 3. Opt-in `--verify-firmware-on-complete`.
- ✅ **Omron FINS UDP fingerprint plugin (port 9600)** — v1.20
  chunk 1.
- ✅ **MELSEC SLMP TCP fingerprint plugin (port 5007)** —
  v1.20 chunk 2.
- ✅ **GE-SRTP TCP fingerprint plugin (port 18245)** —
  v1.20 chunk 3 + v1.21 chunk 4 (model-hint refinement).
- ✅ **KNXnet/IP UDP fingerprint plugin (port 3671)** —
  v1.21 chunk 1.
- ✅ **M-Bus over TCP fingerprint plugin (port 10001)** —
  v1.21 chunk 2.
- ✅ **DLMS/COSEM TCP fingerprint plugin (port 4059)** —
  v1.21 chunk 3.

### v1.44 (proxy replay time-window)

- ✅ **`proxy replay --since/--until`** — v1.44 chunk 1.
  Forensic time-window filter. 4 tests.

### v1.43 (tui --rate slow playback)

- ✅ **`tui --rate N`** — v1.43 chunk 1. Slow-motion
  playback flag. 3 tests.

### v1.42 (replay/record round-trip)

- ✅ **Round-trip closed** — v1.42 chunk 1. `feeds.Replay`
  reads both `ndjson:v1` and `elsereno-tui-record/v1`. The
  v1.41 `--record` output is now consumable by `--replay`.
  8 tests.

### v1.41 (tui --record session capture)

- ✅ **`tui --record FILE.ndjson`** — v1.41 chunk 1.
  Symmetric counterpart to v1.29-chunk-3's --replay. Tees
  every model-bound tea.Msg onto a 0600 NDJSON file
  (`elsereno-tui-record/v1` schema). Best-effort. 8 tests.

### v1.40 (plugins ports reverse index)

- ✅ **`plugins ports` verb** — v1.40 chunk 1. Maps
  port → [plugins] for "which plugin claims 502?" lookups.
  Default plain-text + --json. 4 tests.

### v1.39 (discover --hosts <file>)

- ✅ **`discover --hosts <file>`** — v1.39 chunk 1. Natural
  counterpart to `--auto <CIDR>`. Accepts a curated host
  list (one IP per line, comments OK, host:port-strip,
  IPv6 supported). 7 tests.

### v1.38 (fingerprint capture verb)

- ✅ **`elsereno fingerprint capture` verb** — v1.38
  chunk 1. Natural companion to v1.37's `validate --file`.
  Opens a localhost listener, accepts one connection,
  writes drained bytes to a 0600 file. 4 tests.

### v1.37 (fingerprint validation CLI verb)

- ✅ **`elsereno fingerprint validate` verb** — v1.37
  chunk 1. Closes the v1.28-chunks-1+2 carryover ("ProConOS
  + GE-SRTP confidence ~0.7 pending real-PLC validation").
  Operators with lab access can now self-serve via captured
  bytes (--file or --hex). Works for every registered
  plugin. 13 tests.

### v1.36 (dashboard --input parity)

- ✅ **Dashboard --input parity** — v1.36 chunk 1. Closes
  the v1.31 carryover. New `GET /api/v1/inputs/preview`
  endpoint + `internal/inputs/preview` package. Read-only;
  trigger-from-dashboard scan orchestration is a future
  cycle.

### v1.35 (proxy listen --plugin for 4 legacy-ICS protocols + recording)

- ✅ **proxy listen --plugin pcworx|mms|enip|s7** — v1.35
  chunk 1. Closes the v1.30 carryover; the 4 plugins that
  had Recorder fields but no CLI verb are now first-class
  `--plugin` values with their own allowlist flags
  (--intent / --cip-command / --s7-fc). 13 dispatcher tests
  + 1 invariant pin (every Recorder-having type is in
  attachRecorder).

### v1.34 (tree-wide gosec marker hygiene)

- ✅ **Tree-wide `//nolint:gosec` → `// #nosec G<NNN>`
  migration** — v1.34 chunk 1. 76 markers across 49 files
  in internal/**, offensive/**. PITF-030 now enforced
  tree-wide. Side-fix: corrected a pre-existing
  comment-eats-statement bug in
  `offensive/write/enip/write.go` line 148.

### v1.33 (teatest TUI integration tests)

- ✅ **teatest program-level integration tests for TUI
  runner** — v1.33 chunk 1. Closes the v1.30+v1.31
  carryover. 10 cases cover quit, render, message fold,
  filter-edit cycle, focus cycle, severity-band rendering,
  small-terminal fallback, and clean-output drain.

### v1.32 (cmd/elsereno gosec marker hygiene)

- ✅ **gosec marker hygiene (cmd/elsereno)** — v1.32 chunk 1.
  10 `//nolint:gosec` → `// #nosec G<NNN>` native form
  (PITF-030 / b611f5c convention). Wider tree (~65 markers)
  is its own follow-up — see "🔬 Hygiene & convention parity"
  below.

### v1.31 (TUI input parity with batch scan)

- ✅ **TUI `--input` parity with batch `scan`** — v1.31
  chunk 1. All 8 kinds (list, nmap, stdin, shodan, censys,
  fofa, zoomeye, onyphe, internetdb) now first-class on
  `tui --input KIND`. Shared dispatcher
  (`cmd_input_parse.go`).

### v1.30 (record-replay wire-up to all wire-aware gates + TUI scan launcher + audit filter)

- ✅ **Wire record-replay into the 9 wire-aware gates** —
  v1.30 chunk 1. Closes the v1.28 chunk-3 deferral. sip /
  iax2 / pbxhttp / modbus / opcua / bacnet / cwmp + enip + s7.
- ✅ **`--record FILE` flag on `proxy listen`** — v1.30
  chunk 2. Opens recorder before Authorise so permission
  errors fast-fail.
- ✅ **`elsereno proxy replay FILE` sub-verb** — v1.30 chunk 2.
  Renders captures as `[ts] c→u  NNB  hex…` lines.
- ✅ **TUI scan launcher (`feeds.Interactive`)** — v1.30
  chunk 3. Closes the v1.29 chunk-2 deferral. `--input
  list:FILE` runs `scanner.Scanner` inside the TUI.
- ✅ **TUI audit-pane substring filter** — v1.30 chunk 4.
  `/` → type → Enter; case-insensitive substring match.

### v1.29 (TUI verb + mini build variant)

- ✅ **Mini build variant (`-tags mini`)** — v1.29 chunk 1.
  3-variant goreleaser; mini ~21 MB excludes dashboard + TUI.
- ✅ **Interactive terminal UI** — v1.29 chunks 2-5.
  bubbletea Model/View/Update + 4-pane layout + 4 modes
  (interactive, replay, feed, watch).
- ✅ **TUI protocol doc** — v1.29 chunk 6.
  `.context/tui.md` (architecture + key bindings + wire
  formats + build-tag matrix).

### v1.28 (ProConOS + SRTP service-0x21 + record-replay POC)

- ✅ **ProConOS fingerprint** — v1.28 chunk 1 (best-effort,
  needs real-PLC validation).
- ✅ **GE-SRTP service-0x21 follow-up** — v1.28 chunk 2 (richer
  firmware-version probe; needs real-PLC validation).
- ✅ **Wire record-replay into pcworx + mms gates (POC)** —
  v1.28 chunk 3.

### v1.27 (seccomp wire-up + pcworx/mms gates + record-replay)

- ✅ **Wire seccomp arg-filter presets into ProfileHarvest +
  ProfileDial** — v1.27 chunk 1.
- ✅ **Offensive `pcworx` write-gate** — v1.27 chunk 2 (session-
  level; per-frame deferred).
- ✅ **Offensive `mms` write-gate** — v1.27 chunk 3 (session-
  level; full ASN.1 BER PDU walk is v1.35 MMS-ACSE candidate).
- ✅ **Record & replay primitive** — v1.27 chunk 4 (NDJSON
  capture + replay; integration into each gated proxy is v1.28+).

### v1.26 (audit daemon + seccomp arg-filter primitives)

- ✅ **`elsereno audit serve` daemon (UDS)** — v1.26 chunk 1.
  Centralised single-writer audit daemon over Unix domain
  socket. `audit.Server` + `audit.Client` (Writer-implementing).
  Replaces v1.15-chunk-4 flock at SOC scale.
- ✅ **seccomp-bpf arg-level filtering primitives** — v1.26
  chunk 2 (Linux). ArgDenyRule + Equal/MaskAny modes +
  ArgFilterPresets + CompileFilterWithArgs. Profile integration
  deferred to v1.27.

### v1.25 (CVE coverage closure + 2 new fingerprint plugins)

- ✅ **`cve_exposure` for the v1.20+v1.21 fingerprint trios** —
  v1.25 chunk 1. finsudp=5, slmp=6, gesrtp=5, knxip=6,
  mbustcp=4, dlms=7. 24/27 plugins now publish a non-zero
  cve_exposure (was 16/25 post-v1.24).
- ✅ **PCWorx fingerprint plugin (TCP/1962)** — v1.25 chunk 2.
  Phoenix Contact ILC family + AXC F + RFC PN PLCs.
  cve_exposure:8.
- ✅ **IEC 61850 MMS fingerprint with S7 disambig (TCP/102)** —
  v1.25 chunk 3. COTP TSAP-based disambiguation
  (MMS `00 01`/`00 01` vs S7 `01 00`/`01 02`). cve_exposure:9,
  impact_class:85 (grid-scale).

### v1.22 → v1.24 (CI hygiene + new fingerprints + scoring + docs)

- ✅ **CI hygiene — fuzz-flake retry + explicit `-timeout`** —
  v1.22 chunk 1.
- ✅ **CoDeSys V3 TCP fingerprint plugin (port 1217)** —
  v1.22 chunk 2.
- ✅ **Red Lion Crimson / RLN fingerprint plugin (port 789)** —
  v1.22 chunk 3.
- ✅ **Fuzz coverage expansion 6 → 14 wire packages** —
  v1.22 chunk 4.
- ✅ **CVE-exposure factor — first 9 plugins** — v1.22
  (codesys / redlion) + v1.23 chunk 1 (cwmp / dnp3 / iec104 /
  bacnet / opcua / hartip / atg).
- ✅ **Banner dictionary expansion +21 vendors** — v1.23 chunk 2.
- ✅ **CVE-exposure factor — 7 more plugins** — v1.24 chunk 1
  (s7 / fox / sip / enip / pbxhttp / modbus / iax2). 16/25
  plugins now publish a non-zero `cve_exposure` score.
- ✅ **Engineering notes for the 5 missing plugins** —
  v1.24 chunk 2 (cwmp / opcua / sip / iax2 / pbxhttp).
  `.context/protocols/` is now complete for all 25 plugins.

---

## 🎯 High-leverage — siguiente ciclo (v1.26)

- [ ] **Offensive plugin trio — FINS / SLMP / GE-SRTP** —
  v1.20 shipped read-only fingerprints; the offensive write
  paths (per-CIO write FINS / per-WriteCommand SLMP / per-PLC-
  service GE-SRTP) are pending. Each follows the ADR-040
  template (deny-all default, write-gated offensive variant
  with allowlist + dry-run). Estimación: ~3-4 días total
  (1 chunk per protocol).

- [ ] **Offensive plugin trio — KNX / M-Bus / DLMS** —
  same shape as the FINS/SLMP/SRTP trio above for the v1.21
  fingerprints. Estimación: ~3-4 días total.

- [ ] **MMS ACSE association layer** — v1.25 chunk 3 ships
  COTP-CR-level disambig only. A higher-confidence MMS
  identification would send the OSI session-connect SPDU +
  ACSE A-ASSOCIATE-REQUEST with the IEC 61850-8-1 application-
  context name OID 1.0.9506.2.3 and verify the ACSE accept.
  Estimación: ~6-8h.

- ✅ **Wire record-replay primitive into each gated
  WriteGatedHandler** — pcworx + mms in v1.28 chunk 3 (POC);
  remaining 9 wire-aware gates in v1.30 chunk 1; CLI half
  (`--record` + `proxy replay`) in v1.30 chunk 2.

## 🧰 Herramientas operativas

- ✅ **Record & replay de sesiones de proxy** — primitive in
  v1.27 chunk 4; gate wire-up in v1.28 chunk 3 (POC) + v1.30
  chunk 1 (full); CLI `--record` + `proxy replay` in v1.30
  chunk 2.

## 🔐 Supply-chain + hardening

- ✅ **Wider tree gosec marker convention sweep** — done in
  v1.34 chunk 1 (76 markers across 49 files; PITF-030
  enforced tree-wide).

- [ ] **Sandbox para macOS via `sandbox_init(3)`** — currently
  macOS degrades to "unavailable". A `.sb` Scheme policy
  (no file writes outside cwd, no `exec`) is feasible IF we
  break the pure-Go invariant via cgo to `sandbox_init`.
  **Decisión operador**: aceptar el cgo break o quedarnos en
  unavailable.

## 🔬 Protocolos legacy todavía sin cubrir (2 restantes)

Cada uno = ~6-12h.

- [ ] **PROFINET DCP / GOOSE / SV** (L2, con gopacket —
  necesita `CAP_NET_RAW` + raw-packet capture infrastructure
  que aún no existe en el repo).
- [ ] **OPC UA HTTPS** (additional transport for UA, distinct
  from UA-TCP 4840). HTTP/JSON UA encoding parser needed —
  ~12h.

## 🎨 UX

- [ ] **TUI con bubbletea** — `elsereno tui` que agrupa scan +
  finding stream + triage sin salir del terminal. Brief lo
  mencionó en F4 chunk 2. Decisión operador: aceptar la nueva
  dependencia bubbletea + tcell. ~2-3 días.

- [ ] **Record & replay de sesiones de proxy** — *moved to
  Herramientas operativas above* (more natural fit alongside
  audit daemon).

## 🪟 Plataforma

- [ ] **Windows support**. Bloqueadores: `syscall.*` por-
  plataforma en `internal/audit` (file lock — v1.15 chunk 4
  ya cablea el stub `flock_windows.go`) + el sandbox (Windows
  no tiene seccomp; usaríamos AppContainer / Job Objects).
  Estimación: 3-5 días.

- [ ] **Multi-user OIDC + roles**. Actualmente el dashboard
  tiene un solo operador por proceso. Para SOCs multi-analyst:
  OIDC (Keycloak/Azure AD) + roles (viewer / analyst / admin).
  Estimación: 2-3 días.

---

> Para añadir un ítem: PR con una línea + referencia al ADR o
> issue que lo motiva. Si es >3 días de trabajo, acompáñalo de
> una estimación + dependencias.
