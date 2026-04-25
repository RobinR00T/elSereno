# ElSereno — Forward-looking TODO (vNext)

Complementa a `TODO.md` (la checklist original del brief — closed
tras v1.12.0) y a `ROADMAP.md` (el plan chunked). Aquí se apuntan
ideas de features futuras, superficies de ataque a añadir y
mejoras operativas que surgen en campo.

> Mantén este fichero **corto y accionable**. Cuando un ítem
> entre en un ciclo (v1.x) muévelo a `ROADMAP.md` con su chunk
> asignado + estimación. Cuando cierre, márkalo `✅` con la
> versión y/o el commit.

Last refresh: **2026-04-25** (post-v1.12). Items shipped during
v1.3 → v1.12 archived to keep this file actionable.

---

## ✅ Shipped during v1.3–v1.12

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

---

## 🎯 High-leverage — siguiente ciclo (v1.13)

- [ ] **IPv6 cross-cutting support** (operator-requested
  2026-04-25). Audit `netip.Addr` paths + bind/listen + audit
  log paths + allowlist canonicalisation for v6 host literals
  `[::1]:port`. Likely splits across 3-4 chunks (scan / proxy /
  inputs / write-gates). Estimación: ~1 ciclo completo.

- [ ] **BACnet per-object para los demás mutating services**.
  v1.12 chunk 7 cubre WriteProperty (svc 15). Falta:
    - svc 10 CreateObject — request: ObjectId target.
    - svc 11 DeleteObject — request: ObjectId target.
    - svc 16 WritePropertyMultiple — list of (ObjectId,
      PropertyValues[]); más complejo que 15 (lista de listas).
    - svc 17 DeviceCommunicationControl — devices Disable /
      Disable-Initiation (silenciar dispositivo).
    - svc 20 ReinitializeDevice — coldstart / warmstart.
    - svc 27 LifeSafetyOperation — silence / unsilence alarmas.
    - svc 7 AtomicWriteFile — file Object writes.
    - svc 8/9 Add/RemoveListElement — recipient lists, schedules.
  Cada uno necesita su BER walker + hash extension + tests.
  Estimación: 1 chunk por servicio (8 chunks = 1-2 ciclos).

- [ ] **Bulk InternetDB lookup** — v1.12 chunk 9 cubre
  single-IP. Faltan `internetdb:file:<path>` y `internetdb:-`
  (stdin), uno por línea, con rate-limit upstream ~10 rps.
  Estimación: 1 chunk pequeño.

- [ ] **CWMP TransferComplete-side SHA-256 verification** —
  v1.12 chunk 10 almacena SHA-256 como metadata; falta parsear
  el TransferComplete del CPE → ACS y comparar contra la
  allowlist. Audit on mismatch (firmware corrupto / supply-chain
  attack). Estimación: 1 chunk medio.

## 🧰 Herramientas operativas

- [ ] **`elsereno discover --auto`** — dado un CIDR, ejecuta una
  secuencia nmap-scriptless + port-discovery que combina los
  puertos well-known de todos los plugins y prioriza los que
  responden. Chunk ~1 día.

- [ ] **Triage bucket "utility"** — además de quick-wins /
  strategic / routine añadir un bucket "utility" para servicios
  que exponen información útil pero no son aguja directa (ej.
  banner SSH viejo, HTTP-HEAD con Server: nginx/1.10).

- [ ] **Dashboard: vista de diff entre runs** — comparar dos run
  IDs y resaltar findings nuevos / resueltos / re-apareciendo.
  Útil para operator que corre scans semanales.

- [ ] **Dashboard: filtro por severity + export a CSV en el UI**
  (actualmente sólo vía CLI o `/api/v1/findings`).

- [ ] **SIGHUP reload de proxy listen allowlist** — hoy el
  allowlist se carga al arranque y se mintea el confirm-token
  de la sesión. Permitir SIGHUP con re-mint del token requiere
  un redesign del esquema (cookie de generación). Documentado
  en `.context/STATE.md` "Deferred to v1.13+".

## 🔐 Supply-chain + hardening

- [ ] **seccomp-bpf arg-filtering** — el denylist actual
  bloquea syscalls enteros. Añadir arg-level filtering (ej.
  `openat` permitido sólo con `O_RDONLY`; `socket` permitido
  sólo con `AF_INET`/`AF_INET6`, no `AF_PACKET`).

- [ ] **Sandbox para macOS via `sandbox_init(3)`** —
  actualmente en macOS la sandbox degrada a "unavailable". Una
  `.sb` Scheme policy limitada (no file writes fuera del cwd,
  no `exec`) es factible si salimos del modelo pure-Go (cgo a
  `sandbox_init`).

- [ ] **Audit chain cross-process merge** — si dos procesos
  escriben a `~/.elsereno/audit.jsonl` simultáneamente, hay
  race. Implementar flock + reintento con backoff, o
  idealmente un daemon `elsereno audit serve` al que los
  binarios ofensivos se conectan via uds.

## 🔬 Protocolos legacy no cubiertos (11 restantes)

Cada uno = un ciclo tipo v1.4 chunk 5 + 6.

- [ ] **PROFINET DCP / GOOSE / SV** (L2, con gopacket — necesita
  CAP_NET_RAW)
- [ ] **CoDeSys** runtime (TCP/1200)
- [ ] **Omron FINS** (UDP/9600, TCP/9600)
- [ ] **MELSEC SLMP / 3E-Frame** (Mitsubishi, TCP/5007)
- [ ] **PCWorx / Phoenix Contact ILC** (TCP/1962)
- [ ] **ProConOS** (TCP/20547)
- [ ] **Red Lion Crimson 3.0** (TCP/789)
- [ ] **GE-SRTP** (TCP/18245)
- [ ] **IEC 61850 MMS** (TCP/102 shared with S7 — disambig
  required)
- [ ] **KNX / EIB** (UDP/3671)
- [ ] **M-Bus TCP** (TCP/502 shared with Modbus — disambig)
- [ ] **OPC UA HTTPS** (additional transport for UA, distinct
  from the UA-TCP 4840 ElSereno already covers)
- [ ] **DLMS/COSEM** (IEC 62056-46, TCP/4059/4061)

## 🎨 UX

- [ ] **TUI con bubbletea** — `elsereno tui` que agrupa scan +
  finding stream + triage sin salir del terminal. Brief lo
  mencionó en F4 chunk 2; aún pendiente.

- [ ] **Record & replay** de sesiones de proxy — grabar el
  tráfico cliente↔server cuando un operador acepta writes, con
  timestamps, para replay en laboratorio. Útil para post-
  mortems + capacitación.

## 🪟 Plataforma

- [ ] **Windows support**. El bloqueador principal son los
  `syscall.*` por-plataforma en `internal/audit` (file lock) +
  el sandbox (Windows no tiene seccomp; podríamos usar
  AppContainer / Job Objects).

- [ ] **Multi-user OIDC + roles**. Actualmente el dashboard
  tiene un solo operador por proceso. Para SOCs multi-analyst:
  OIDC (Keycloak/Azure AD) + roles (viewer / analyst / admin).

- [ ] **STIX 2.1 export** — cada finding → un `indicator` +
  `observed-data` SDO. Permitiría compartir hallazgos con
  plataformas threat-intel.

---

> Para añadir un ítem: PR con una línea + referencia al ADR o
> issue que lo motiva. Si es >3 días de trabajo, acompáñalo de
> una estimación + dependencias.
