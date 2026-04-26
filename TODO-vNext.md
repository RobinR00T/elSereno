# ElSereno — Forward-looking TODO (vNext)

Complementa a `TODO.md` (la checklist original del brief — closed
tras v1.12.0) y a `ROADMAP.md` (el plan chunked). Aquí se apuntan
ideas de features futuras, superficies de ataque a añadir y
mejoras operativas que surgen en campo.

> Mantén este fichero **corto y accionable**. Cuando un ítem
> entre en un ciclo (v1.x) muévelo a `ROADMAP.md` con su chunk
> asignado + estimación. Cuando cierre, márkalo `✅` con la
> versión y/o el commit.

Last refresh: **2026-04-26** (post-v1.15). Items shipped during
v1.3 → v1.15 archived to keep this file actionable.

---

## ✅ Shipped during v1.3–v1.15

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
- ✅ **InternetDB bulk lookup** — v1.13 chunk 1
  (`internetdb:file:` + `internetdb:-`).
- ✅ **CWMP firmware pre-flight verifier** — v1.13 chunk 2
  (`elsereno-offensive write cwmp verify-firmware`).
- ✅ **BACnet per-object for WritePropertyMultiple (svc 16)** —
  v1.13 chunk 3.
- ✅ **CWMP RPC-name case-warning in dry-run** — v1.13 chunk 4.
- ✅ **CWMP-over-TLS operator recipe** — v1.13 chunk 5 (docs
  only; nginx + HAProxy + Caddy front-proxy patterns).
- ✅ **Triage bucket "utility"** — v1.13 chunk 6 (4th bucket
  alongside quick-win / strategic / routine).
- ✅ **BACnet per-target / per-state / per-operation /
  per-instance / per-(object,property) scoping for the
  remaining 7 mutating services** — v1.13 chunks 7-13 closes
  every BACnet mutating service (svc 7/8/9/10/11/15/16/17/20/27)
  at natural granularity (per-target DeleteObject, per-type
  CreateObject, per-state ReinitializeDevice and DCC, per-op
  LSO, per-File AtomicWriteFile, per-(object,property)
  Add/RemoveListElement). Per-instance Create + per-object LSO
  refinements remain v1.16+ tightenings if operators ask.
- ✅ **IPv6 cross-cutting support** — v1.14 (4 chunks).
  `internal/netutil` package with `IsLoopbackHostPort` +
  `CanonicalHostPort` + `ParseAddrPort`; target
  canonicalisation across proxy listen + every dry-run command;
  `scan --input internetdb:` v6 dispatcher fix +
  bracket-stripping ergonomics; scope/dedupe IPv6 contract
  tests pinned.
- ✅ **CWMP TransferComplete observer (parsing half)** — v1.15
  chunk 1. Opt-in callback fires when CPE → ACS
  TransferComplete envelopes traverse the gate; default CLI
  observer emits structured stderr log lines. The remaining
  half — comparing the reported success against the v1.12
  chunk-10 firmware-allowlist metadata and emitting an
  audit-on-mismatch event — is the v1.16+ candidate below.
- ✅ **`elsereno discover --auto <CIDR>`** — v1.15 chunk 2.
  TCP-connect sweep iterates the CIDR + probes the well-known
  port of every registered plugin. Pipe-friendly with
  `scan --input list:-` for the point-and-shoot inventory
  workflow.
- ✅ **STIX 2.1 export** — v1.15 chunk 3.
  `--output-format stix` emits findings as a STIX bundle
  (ipv4/ipv6-addr SCO + network-traffic SRO + indicator SDO)
  with deterministic UUIDv5 IDs. Feeds into MISP / OpenCTI /
  ThreatBus.
- ✅ **Audit chain cross-process merge via flock** — v1.15
  chunk 4. POSIX `flock(LOCK_EX)` serialises Append +
  appendVerbatim; second writer resumes from the latest tail
  under the lock so the chain stays consistent across
  concurrent processes.
- ✅ **SIGHUP reload of proxy listen allowlist (supervisor
  variant)** — v1.15 chunk 5. SIGHUP triggers a clean exit
  with code 75 / EX_TEMPFAIL distinguishable from real crashes
  via `RestartPreventExitStatus=`; supervisor restarts with the
  new allowlist + freshly minted confirm-token. The in-process
  reload variant (token-generation cookie scheme that avoids
  the restart) is the v1.16+ candidate below.

---

## 🎯 High-leverage — siguiente ciclo (v1.16)

- [ ] **CWMP TransferComplete SHA-256 mismatch audit** — v1.15
  chunk 1 added the parsing half; falta correlar el envelope
  contra la entrada de audit del Download autorizado (v1.12
  chunk 10 guarda el `firmware_url` + `sha256` allowlisted) y
  emitir un evento de audit enriquecido (`outcome=succeeded`
  con cross-reference al Download, `outcome=failed` con
  fault_code/fault_string, `outcome=orphan_complete` si la
  CommandKey no aparece en la cadena). Estimación: 1 chunk
  medio.

- [ ] **BACnet per-instance CreateObject + per-object
  LifeSafetyOperation scoping** — v1.13 cerró los 9 servicios
  al "natural granularity" (CreateObject por tipo,
  LifeSafetyOperation por operación). Refinar a per-instance
  CreateObject (`type+instance` exact-match) + per-object LSO
  (`type+instance` para acotar el silenciado/reset a un
  Life-Safety-Point específico). Estimación: 1 chunk pequeño
  por servicio (2 chunks).

- [ ] **In-process allow-file reload (alternative to v1.15
  chunk 5 supervisor pattern)** — el supervisor-restart cierra
  el caso operativo, pero requiere systemd / runit / similar.
  La alternativa in-process necesita un esquema de cookie de
  generación de confirm-token (paralelo al `web_state.
  token_generation` del dashboard) para invalidar tokens
  vivos al recargar. Estimación: 1 chunk medio.

## 🧰 Herramientas operativas

- [ ] **Dashboard: vista de diff entre runs** — comparar dos run
  IDs y resaltar findings nuevos / resueltos / re-apareciendo.
  Útil para operator que corre scans semanales.

- [ ] **Dashboard: filtro por severity + export a CSV en el UI**
  (actualmente sólo vía CLI o `/api/v1/findings`).

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

- [ ] **`elsereno audit serve` daemon (UDS)** — v1.15 chunk 4
  cierra el race entre procesos vía flock; un daemon
  centralizado al que los binarios ofensivos se conecten via
  Unix domain socket es la alternativa más limpia para
  fan-in masivo (un único writer single-threaded; los demás
  procesos solo emiten via UDS). v1.16+ si flock se queda
  corto en escala.

## 🔬 Protocolos legacy no cubiertos (12 restantes)

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
  `syscall.*` por-plataforma en `internal/audit` (file lock —
  v1.15 chunk 4 ya cablea el stub `flock_windows.go`) +
  el sandbox (Windows no tiene seccomp; podríamos usar
  AppContainer / Job Objects).

- [ ] **Multi-user OIDC + roles**. Actualmente el dashboard
  tiene un solo operador por proceso. Para SOCs multi-analyst:
  OIDC (Keycloak/Azure AD) + roles (viewer / analyst / admin).

---

> Para añadir un ítem: PR con una línea + referencia al ADR o
> issue que lo motiva. Si es >3 días de trabajo, acompáñalo de
> una estimación + dependencias.
