# ElSereno — Forward-looking TODO (vNext)

Complementa a `TODO.md` (la checklist original del brief — closed
tras v1.12.0) y a `ROADMAP.md` (el plan chunked). Aquí se apuntan
ideas de features futuras, superficies de ataque a añadir y
mejoras operativas que surgen en campo.

> Mantén este fichero **corto y accionable**. Cuando un ítem
> entre en un ciclo (v1.x) muévelo a `ROADMAP.md` con su chunk
> asignado + estimación. Cuando cierre, márkalo `✅` con la
> versión y/o el commit.

Last refresh: **2026-04-30** (post-v1.24). Items shipped during
v1.3 → v1.24 archived to keep this file actionable.

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

## 🎯 High-leverage — siguiente ciclo (v1.25)

- [ ] **`cve_exposure` for the v1.20 / v1.21 fingerprint trios** —
  finsudp / slmp / gesrtp / knxip / mbustcp / dlms still publish
  0 (unchanged from v1.20 introduction). Public CVE histories
  are sparse on these (proprietary protocols, low public scan
  visibility), but a conservative non-zero score per plugin is
  better than 0 once a single anchor CVE family lands. Target
  cve_exposure ∈ [3, 8] each. Estimación: 1 chunk pequeño.

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

- [ ] **GE-SRTP service-0x21 follow-up** — v1.21 chunk 4 added
  the model-hint extraction; service 0x21 carries richer
  firmware-version data that's currently parsed shallowly.
  Estimación: ~4-6h.

- [ ] **PCWorx / Phoenix Contact ILC fingerprint (TCP/1962)** —
  follows the v1.20-v1.22 plugin shape. Phoenix Contact's
  ILC PLC family. Estimación: ~6h.

- [ ] **ProConOS fingerprint (TCP/20547)** — same shape.
  Phoenix Contact / KW-Software runtime, ships on multiple
  PLC brands. Estimación: ~6h.

- [ ] **IEC 61850 MMS fingerprint (TCP/102, disambig vs S7)** —
  port 102 is shared with S7 (TPKT/COTP wrapper). Disambig is
  on the COTP-CR Connect-Request: S7 uses a specific
  Calling/Called TSAP pair, MMS uses the IEC 61850 ACSE
  initiate-request. Estimación: ~8h (more careful than the
  v1.21 trio because of the disambig logic).

## 🧰 Herramientas operativas

- [ ] **`elsereno audit serve` daemon (UDS)** — v1.15 chunk 4
  closed the cross-process race via POSIX flock; a centralised
  daemon over a Unix domain socket is the cleaner alternative
  for SOC-scale fan-in (a single single-threaded writer; other
  processes emit-only). v1.25+ if flock's contention curve
  bites in field deployments.

## 🔐 Supply-chain + hardening

- [ ] **seccomp-bpf arg-filtering** — the v1.1 chunk 6 denylist
  blocks syscalls whole-cloth; arg-level filters tighten further
  (e.g. `openat` permitted only with `O_RDONLY`; `socket`
  permitted only with `AF_INET` / `AF_INET6`, refusing
  `AF_PACKET`). Linux only. Estimación: 1 chunk medio.

- [ ] **Sandbox para macOS via `sandbox_init(3)`** — currently
  macOS degrades to "unavailable". A `.sb` Scheme policy
  (no file writes outside cwd, no `exec`) is feasible IF we
  break the pure-Go invariant via cgo to `sandbox_init`.
  **Decisión operador**: aceptar el cgo break o quedarnos en
  unavailable.

## 🔬 Protocolos legacy todavía sin cubrir (4 restantes)

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

- [ ] **Record & replay de sesiones de proxy** — grabar el
  tráfico cliente↔server cuando un operador acepta writes,
  con timestamps, para replay en laboratorio. Útil para
  post-mortems + capacitación. ~1-2 días.

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
