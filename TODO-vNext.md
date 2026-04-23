# ElSereno — Forward-looking TODO (vNext)

Complementa a `TODO.md` (la checklist original del brief) y a
`ROADMAP.md` (el plan chunked). Aquí se apuntan ideas de features
futuras, superficies de ataque a añadir y mejoras operativas que
surgen en campo.

> Mantén este fichero **corto y accionable**. Cuando un ítem
> entre en un ciclo (v1.x) muévelo a `ROADMAP.md` con su chunk
> asignado + estimación.

---

## 🎯 High-leverage — siguiente ciclo v1.3

- [ ] **Buscar PBX expuestas (Asterisk y similares)** — la superficie
  telefónica (VoIP / PBX / SBC) es enorme y poco cubierta por
  herramientas ICS. Añadir un plugin `pbx` que haga fingerprint
  sobre:
    - **Asterisk**: SIP 5060/udp/tcp + AMI 5038/tcp (Asterisk
      Manager Interface banner) + ARI 8088/tcp (`/ari/api-docs`
      HTTP) + IAX2 4569/udp.
    - **FreePBX**: 80/443 con `/admin/config.php` banner, cookie
      `fpbxrec`, admin login page.
    - **Cisco CallManager / UCM**: 2000/tcp SCCP + 5060/tcp SIP
      + 8080/443 admin.
    - **3CX**: 5060/5061 + 5000/tcp management + WebRTC web UI
      banner.
    - **Mitel**: 6801/tcp MICC + 6804/tcp + 7001 UI.
    - **Avaya IP Office**: 50791/tcp SSA + 411 TLS.
    - **Yeastar / Grandstream / Fanvil / Yealink** SOHO PBXs:
      SIP fingerprint + HTTP admin pages.
  Cada uno con un detector ASCII-banner + (cuando aplica) un
  HTTP fingerprint (cabecera `Server`, favicon hash, title). El
  scoring `protocol_risk` para PBX expuestas en Internet es
  ≈ 85 (robo de minutos, fraude toll, escucha interna).
  Chunk estimado: ~4 días. Dependencias: ninguna (el scanner
  actual soporta ya UDP + HTTP banner).

- [ ] **SIP scan mode dedicado** — OPTIONS + REGISTER probes
  contra /udp/tcp/tls 5060/5061. Clasificar respuestas por
  `User-Agent` header, enumerar extensiones REGISTER (con
  guarda ≤ 3 dígitos + scope.blocked_extensions). Chunk ~2 días.

- [ ] **IAX2 fingerprint** — protocolo binario de Asterisk.
  Paquete NEW + paquete HANGUP. Útil cuando SIP está bloqueado
  pero IAX2 sigue expuesto a Internet en despliegues legacy.

- [ ] **TR-069 / CWMP** (CPE WAN Management Protocol) — SOAP
  sobre HTTP/7547 que muchos ISPs dejaron expuesto. Banner HTTP
  + `<cwmp:Inform>` probe.

- [ ] **Wardial batch con backend real (VoIP SIP)** — v1.2
  chunk 4 dejó la interfaz `Backend` + `Mock` + `ATModem`
  listos. Falta el `voip-sip` backend corriendo en subproceso
  (el sandbox `dial` bloquea sockets en el parent). Spec:
  INVITE + ACK + BYE contra un proxy SIP configurable
  (`--sip-proxy`, `--sip-user`, `--sip-pass-file`).

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

## 🔐 Supply-chain + hardening

- [ ] **SLSA v2.1.0 upstream fix** — v1.1/v1.2 llevan el gate
  non-blocking. Dropear el reusable workflow + llamar al
  generator directo ya está en v1.2 chunk 5 (parte del plan),
  pero si v1.2 queda sin completarlo, sigue pendiente en v1.3.

- [ ] **seccomp-bpf arg-filtering** — el denylist actual
  (v1.1 chunk 6) bloquea syscalls enteros. Añadir arg-level
  filtering (ej. `openat` permitido sólo con `O_RDONLY`;
  `socket` permitido sólo con `AF_INET`/`AF_INET6`, no
  `AF_PACKET`).

- [ ] **Sandbox para macOS via `sandbox_init(3)`** — actualmente
  en macOS la sandbox degrada a "unavailable". Una `.sb` Scheme
  policy limitada (no file writes fuera del cwd, no `exec`)
  es pegajosa pero factible si salimos del modelo pure-Go
  (cgo a `sandbox_init`). Recolección de preferencias
  primero.

- [ ] **Audit chain cross-process merge** — si dos procesos
  escriben a `~/.elsereno/audit.jsonl` simultáneamente, hay
  race. Los operadores en un SOC con varios analistas pueden
  chocar. Implementar flock + reintento con backoff, o
  idealmente un daemon `elsereno audit serve` al que los
  binarios ofensivos se conectan via uds.

## 🌐 Inputs + integraciones

- [ ] **ONYPHE** input: `elsereno scan --input-type onyphe
  --api-key-file ...`.
- [x] **FOFA** input — fofa.info. ✅ Librería landed en v1.8
  chunk 1 (`internal/inputs/fofa`). email+qbase64 auth. CLI
  wire-up pendiente (ver `CLI wire-up` más abajo).
- [x] **ZoomEye** input — zoomeye.org. ✅ Librería landed en
  v1.8 chunk 2 (`internal/inputs/zoomeye`). `API-KEY` header.
  CLI wire-up pendiente.
- [ ] **CLI wire-up para FOFA + ZoomEye + Shodan + Censys** —
  hoy los 4 clientes son librerías sin CLI. Opciones:
  (a) extender `--input fofa:<query>` / `--input zoomeye:<q>`
      con `--api-creds-file <path>` para las creds;
  (b) nuevo verbo `elsereno search fofa --query <q>
      --creds-file <path>` que saca NDJSON a stdout, que se
      pipea a `elsereno scan --input stdin`;
  (c) integración con vault (`elsereno creds store fofa` +
      auto-uso desde `scan`).
  (c) es lo más consistente con el resto del codebase.
- [ ] **Shodan InternetDB** (libre, sin key): CDN-friendly
  endpoint `/host/<ip>`.
- [ ] **STIX 2.1 export**: cada finding → una `indicator` +
  `observed-data` SDO. Permitiría compartir hallazgos con
  plataformas threat-intel.

## 🔬 Protocolos legacy no cubiertos

- [ ] **PROFINET DCP / GOOSE / SV** (L2, con gopacket)
- [ ] **CoDeSys** runtime (TCP/1200)
- [ ] **Omron FINS** (UDP/9600, TCP/9600)
- [ ] **MELSEC SLMP / 3E-Frame** (Mitsubishi, TCP/5007)
- [ ] **PCWorx / Phoenix Contact ILC** (TCP/1962)
- [ ] **ProConOS** (TCP/20547)
- [ ] **Red Lion Crimson 3.0** (TCP/789)
- [ ] **GE-SRTP** (TCP/18245)
- [ ] **IEC 61850 MMS** (TCP/102 shared with S7, disambig
  required)
- [ ] **KNX / EIB** (UDP/3671)
- [ ] **M-Bus TCP** (TCP/502 shared with Modbus, disambig)
- [ ] **OPC UA HTTPS** (additional transport for UA, distinct
  from the UA-TCP 4840 ElSereno already covers).
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

- [ ] **Windows support**. El brief lo lista como vNext. El
  bloqueador principal son los `syscall.*` por-plataforma en
  `internal/audit` (file lock) + el sandbox (Windows no tiene
  seccomp; podríamos usar AppContainer / Job Objects).

- [ ] **Multi-user OIDC + roles**. Actualmente el dashboard
  tiene un solo operador por proceso. Para SOCs multi-analyst:
  OIDC (Keycloak/Azure AD) + roles (viewer / analyst / admin).

---

> Para añadir un ítem: PR con una línea + referencia al ADR o
> issue que lo motiva. Si es >3 días de trabajo, acompáñalo de
> una estimación + dependencias.
