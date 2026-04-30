# ElSereno — Forward-looking TODO (vNext)

Complementa a `TODO.md` (la checklist original del brief — closed
tras v1.12.0) y a `ROADMAP.md` (el plan chunked). Aquí se apuntan
ideas de features futuras, superficies de ataque a añadir y
mejoras operativas que surgen en campo.

> Mantén este fichero **corto y accionable**. Cuando un ítem
> entre en un ciclo (v1.x) muévelo a `ROADMAP.md` con su chunk
> asignado + estimación. Cuando cierre, márkalo `✅` con la
> versión y/o el commit.

Last refresh: **2026-04-30** (post-v1.26). Items shipped during
v1.3 → v1.26 archived to keep this file actionable.

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

- [ ] **GE-SRTP service-0x21 follow-up** — v1.21 chunk 4 added
  the model-hint extraction; service 0x21 carries richer
  firmware-version data that's currently parsed shallowly.
  **Blocked**: needs real-PLC test vectors (Mark VIe / RX3i /
  PACSystems) — public references differ on the byte layout.
  Estimación: ~4-6h once vectors are available.

- [ ] **ProConOS fingerprint (TCP/20547)** — Phoenix Contact /
  KW-Software runtime, ships on multiple PLC brands.
  **Blocked**: conflicting public wire-layer references
  (`ca fe / de ca de c0` vs `01 06 00 10 + "PROCONOS"`); needs
  disambig research + test vectors. Estimación: ~6h once
  vectors are available.

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

- [ ] **Offensive `pcworx` / `mms` write-gated proxies** — v1.25
  chunks 2-3 ship fail-closed default proxies for both new
  plugins. The offensive write-gated variants follow the
  ADR-040 template. Estimación: ~1 día each.

## 🧰 Herramientas operativas

- [ ] **Record & replay de sesiones de proxy** — graba el
  tráfico cliente↔server en sesiones offensive con timestamps
  para post-mortem + capacitación en lab. Pairs naturally with
  the v1.26 audit daemon (the daemon could fan-in not just
  audit events but also wire-tapped proxy session bytes).
  v1.27+ candidate.

## 🔐 Supply-chain + hardening

- [ ] **Wire seccomp arg-filter presets into specific
  sandbox profiles** — v1.26 chunk 2 shipped the building
  blocks (ArgDenyRule + ArgFilterPresets + CompileFilterWithArgs).
  v1.27 candidate: decide which preset goes into which profile
  (ProfileHarvest → openat-no-write; ProfileDial →
  socket-deny-AF_PACKET-AF_NETLINK; ProfileExploit → likely
  no preset because exploits sometimes legitimately need
  openat(O_CREAT)). Estimación: ~3-4h for the wiring + tests.

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
