# ElSereno — Manual de casos de uso

*Para operadores de seguridad OT/ICS que hacen descubrimiento,
fingerprint y test autorizado de protocolos industriales legacy.*

**Versión del manual**: v1.14.0 (ciclo cerrado, tag pendiente)
· 2026-04-26
**Compatible con binario**: v1.13.0+ (cierra TODOS los
servicios mutating BACnet — svc 7/8/9/10/11/15/16/17/20/27).
**v1.14.0** añade soporte IPv6 cross-cutting: nuevo paquete
`internal/netutil`, canonicalización IPv6 en `--target` /
`--listen` / `--confirm-target`, fix del dispatcher
`scan --input internetdb:`, bracket-stripping para
`[2001:db8::1]`, scope + dedupe IPv6 contract tests.

---

## Novedades v1.14.0 (IPv6 cross-cutting)

Cycle de 4 chunks operator-requested 2026-04-25.

- **Chunk 1** — Nuevo paquete `internal/netutil` con
  helpers IsLoopbackHostPort / CanonicalHostPort /
  ParseAddrPort. Reemplaza la fragile substring-based
  loopback check de `cmd_serve.go` (no detectaba `[0:0:0:0:
  0:0:0:1]`, `[::1%lo0]`, ni 127.0.0.5/8).
- **Chunk 2** — Canonicalización de target / listen /
  confirm-target. Operador que escribe
  `[0:0:0:0:0:0:0:1]:7547` en dry-run y `[::1]:7547` en
  proxy listen ahora ve ambas formas convergir al mismo
  string canónico (RFC 5952). Hash matches → confirm-token
  works.
- **Chunk 3** — `scan --input internetdb:` dispatcher fix
  (regression de v1.13 chunk 1) + bracket-stripping para
  IPv6 literals (`[2001:db8::1]` ahora funciona).
- **Chunk 4** — IPv6 coverage tests para scope + dedupe
  paths. Audit-only: la infraestructura `netip.Addr` +
  `Unmap()` ya estaba correcta; los tests pinnan el
  contrato.

Backwards compat: IPv4 sin cambios; IPv6 already-canonical
sin cambios. Solo operadores con tokens minted desde IPv6
longform / uppercase necesitan re-mint.

Snapshot completo:
[`.context/snapshots/v1.14.0-ipv6-cross-cutting.md`](
../../.context/snapshots/v1.14.0-ipv6-cross-cutting.md).

---

## Novedades v1.13.0

Trece chunks han aterrizado. **Cierre completo de la dimensión
BACnet** — los 9 servicios destructivos (svc 7/8/9/10/11/15/16/
17/20/27) tienen ahora wire-level per-target-or-state allowlists.

### Servicios BACnet completados

| svc | Servicio                       | Granularidad                  | Flag CLI                                |
|-----|--------------------------------|-------------------------------|-----------------------------------------|
| 7   | AtomicWriteFile                | per-File-instance             | `--awf-file N`                          |
| 8   | AddListElement                 | per-(type, instance, prop)    | `--list-element type=N;instance=M;property=P` |
| 9   | RemoveListElement              | per-(type, instance, prop) †  | `--list-element …` (compartido)         |
| 10  | CreateObject                   | per-type (instance ignorado)  | `--create-object-type N`                |
| 11  | DeleteObject                   | per-(type, instance)          | `--delete-object type=N;instance=M`     |
| 15  | WriteProperty (v1.12)          | per-(type, instance, prop)    | `--object type=N;instance=M;property=P` |
| 16  | WritePropertyMultiple          | per-tuple, batch walker       | `--object …` (compartido con svc 15)    |
| 17  | DeviceCommunicationControl     | per-state (enableDisable)     | `--dcc-state N`                         |
| 20  | ReinitializeDevice             | per-state (state-of-device)   | `--reinit-state N`                      |
| 27  | LifeSafetyOperation            | per-operation                 | `--lso-op N`                            |

† svc 8 + 9 comparten la misma allowlist `--list-element`.

### Otras mejoras v1.13

- **CWMP firmware pre-flight verifier**:
  `elsereno-offensive write cwmp verify-firmware
  --firmware url=…;sha256=…`. HEAD → GET, calcula SHA-256
  sobre el body, compara con el pin. Output OK / MISMATCH /
  UNREACHABLE.
- **CWMP RPC case-warning** en dry-run (TR-069 §A.4).
- **CWMP-over-TLS operator recipe** (nginx / HAProxy / Caddy
  front-proxy).
- **InternetDB bulk lookup**: `--input internetdb:file:<path>`
  o `internetdb:-` (stdin).
- **Triage `utility` bucket**: 4ª prioridad entre `strategic`
  y `routine`.

Snapshot completo:
[`.context/snapshots/v1.13.0-bacnet-completion-and-cwmp-polish.md`](
../../.context/snapshots/v1.13.0-bacnet-completion-and-cwmp-polish.md).

---

## Novedades v1.11 / v1.12

**v1.11.0** (2026-04-24) — CWMP/TR-069 offensive proxy.
Allowlist por SOAP RPC para tráfico ACS-CPE. RPCs read-only +
protocol-flow (GetParameter*, Inform, TransferComplete, …)
pasan siempre; los write-capable (SetParameterValues, Reboot,
Download, FactoryReset, …) requieren `--rpc <Name>` explícito.
Refusal: SOAP Fault 9001 "Request denied" + cabecera
`X-Elsereno-Gate-Reason`. Ver §6.5 (CWMP).

**v1.12.0** (2026-04-25) — gates tightening + paginación de
inputs. Cada gate ya escopa por identidad fina:

- **CWMP**: `--param-prefix InternetGatewayDevice.WANDevice.`
  para tightening de Set* RPCs; `--firmware url=…;sha256=…`
  para limitar Download a imágenes concretas.
- **OPC UA**: walk de cada WriteValue (no solo el primero);
  `--node-id ns=N;{i,s,g,b}=…` admite los cuatro encodings
  (numeric / String / GUID / ByteString); `--call-method
  object=…;method=…` para CallRequest.
- **Modbus**: `--write unit=N;fc=M;start=A;end=B` estructurado;
  round-trip lossless con `--emit-allow-file`.
- **SIP**: `--from-domain HOST` (identity-spoof guard).
- **BACnet**: `--object type=N;instance=M;property=P` para
  WriteProperty (svc 15) con BER walker.
- **Inputs**: paginación automática hasta 1000 hits across
  shodan/censys/fofa/zoomeye/onyphe (cierra el "page 1 only"
  carry-over). Nuevo provider `internetdb:<ip>` sin API key
  (rate-limit upstream ~10 rps).

Ladders de hash backwards-compat: si no usas los flags nuevos,
los confirm-tokens v1.4–v1.11 siguen valiendo.

Snapshot completo:
[`.context/snapshots/v1.12.0-gates-tightening-and-inputs.md`](
../../.context/snapshots/v1.12.0-gates-tightening-and-inputs.md).

---

## 0. Aviso legal + uso autorizado

ElSereno es una herramienta **dual-use**. La capacidad "offensive"
existe exclusivamente para operaciones con **contrato escrito,
scope aprobado por el propietario del sistema y ventana de
mantenimiento declarada**. Sin esas tres cosas, **NO la uses**:

- Un `write modbus send` fuera de scope puede **parar una
  planta real**.
- Un `dial` mal numerado puede llamar a servicios de emergencia
  (el guard ≤3 dígitos lo bloquea, pero +34 91 911 … no).
- Un `exploit run` sobre un PLC en producción puede dejarlo
  **colgado** hasta ciclo de alimentación.

El binario default es **totalmente read-only** y seguro. El
binario offensive requiere (a) build tag, (b) `--accept-writes`,
(c) `--confirm-target`, (d) `--confirm-token` (HMAC derivado del
vault). Cada acción se auditéa en cadena hash.

---

## 1. Instalación + primer arranque

### 1.1 Instalación desde release firmada (v1.8.0+)

```sh
VERSION=1.8.0
OS=darwin          # o linux
ARCH=arm64         # o amd64
BASE="https://github.com/RobinR00T/elSereno/releases/download/v${VERSION}"

# Descargar el tarball + checksums + SBOM
curl -fLo "elsereno_${VERSION}.tar.gz" \
  "${BASE}/elsereno_${VERSION}_${OS}_${ARCH}.tar.gz"
curl -fLo checksums.txt "${BASE}/checksums.txt"
curl -fLo "elsereno_${VERSION}.tar.gz.cyclonedx.json" \
  "${BASE}/elsereno_${VERSION}_${OS}_${ARCH}.tar.gz.cyclonedx.json"

# Integridad SHA-256
shasum -a 256 -c checksums.txt --ignore-missing

# Desempaquetar
tar xzf "elsereno_${VERSION}.tar.gz"

# Dos binarios dentro del tar:
#   elsereno            — build por defecto (read-only, safe)
#   elsereno-offensive  — build -tags offensive (write/exploit/…)
./elsereno_${VERSION}_${OS}_${ARCH}/elsereno version
./elsereno_${VERSION}_${OS}_${ARCH}/elsereno plugins list | wc -l   # 17
```

### 1.2 Verificar el tag GPG firmado

El tag `v1.8.0` está firmado con la clave del maintainer. Es el
método de verificación canónico desde v1.8.0 (cosign keyless /
SLSA requieren CI facturada y no aplican al free-tier flow).

```sh
# Importar la clave pública
curl -fL https://github.com/RobinR00T.gpg | gpg --import

# O pedirla al keyserver (si está publicada):
gpg --keyserver keys.openpgp.org --recv-keys ACE3B86BACACE7D6

# Clonar + verificar
git clone https://github.com/RobinR00T/elSereno.git
cd elSereno
git tag -v v1.8.0
# → "Good signature from Daniel Solís Agea <daniel.solis@zynap.com>"
```

### 1.3 Build desde fuentes (reproducible)

```sh
git clone https://github.com/RobinR00T/elSereno.git
cd elSereno
git checkout v1.8.0

# Build default
make build          # → bin/elsereno

# Build offensive
make build-offensive  # → bin/elsereno-offensive

# O todo vía goreleaser (mismo flujo que la release oficial):
goreleaser release --clean --skip=publish,sign,docker,validate
shasum -a 256 dist/elsereno_*.tar.gz
# → debe coincidir con checksums.txt de la release publicada
```

### 1.4 Docker (v1.1–v1.7 — sólo si restaurás Actions billing)

El docker image en `ghcr.io/robinr00t/elsereno:*` queda en
releases anteriores con Actions activo. Para v1.8.0 no hay
imagen pública (sin CI billing). Para build local:

```sh
docker buildx build --platform linux/amd64,linux/arm64 \
  -t local/elsereno:v1.8.0 .
docker run --rm local/elsereno:v1.8.0 version
```

### 1.5 Primer arranque — vault + dashboard

```sh
# Inicializa el vault cifrado (Argon2id + AES-GCM)
elsereno vault init
# Pide passphrase dos veces

# Desbloquea interactivamente
elsereno vault unlock

# Arranca el dashboard HTTP en loopback (requiere vault desbloqueado)
elsereno serve --addr 127.0.0.1:8787

# En otra terminal
open http://127.0.0.1:8787
```

Para arranque no-interactivo (CI, agente, docker):

```sh
umask 077
printf '%s' "$MY_PASSPHRASE" > ~/.elsereno/dev.pp
chmod 0600 ~/.elsereno/dev.pp
elsereno vault init   --vault-passphrase-file ~/.elsereno/dev.pp
elsereno serve        --vault-passphrase-file ~/.elsereno/dev.pp
```

### 1.6 Dashboard con Postgres (opcional, v1.2+)

Sin `$DATABASE_URL`, los paneles de findings/triage/runs
responden 503 y la UI muestra "backend unavailable". Los paneles
overview / plugins / live-feed / security siguen funcionando
100% sin BD — la BD es sólo para historia persistida.

#### 1.6.1 Con el script helper (`scripts/dev-db.sh`)

ElSereno ships un script que arranca la dev-db + espera health
+ aplica migrations + deja el `DATABASE_URL` en un fichero 0600:

```sh
# Arranca Postgres 16 en loopback 5433 + aplica migrations
scripts/dev-db.sh up

# Otros verbs
scripts/dev-db.sh status   # ps + pg_isready
scripts/dev-db.sh env      # imprime la línea export DATABASE_URL=...
scripts/dev-db.sh down     # para el contenedor (volumen preservado)
scripts/dev-db.sh reset    # borra el volumen + re-up + migrate
```

El script escribe `~/.elsereno/dev-db.env` con:
```
DATABASE_URL=postgres://elsereno@127.0.0.1:5433/elsereno?sslmode=disable
```

Para cargarlo en tu shell + arrancar serve:

```sh
export $(grep -v '^#' ~/.elsereno/dev-db.env | xargs)
elsereno serve --vault-passphrase-file ~/.elsereno/dev.pp
```

#### 1.6.2 Manual (sin script)

Si prefieres no usar el script:

```sh
docker compose -f docker-compose.dev.yml up -d db
export DATABASE_URL="postgres://elsereno@127.0.0.1:5433/elsereno?sslmode=disable"
elsereno db migrate up
elsereno serve
```

#### 1.6.3 Matriz "¿necesito BD?"

| Feature | Requiere `$DATABASE_URL`? |
|---------|--------------------------|
| `scan` → NDJSON/CSV/HTML | No |
| `serve` + dashboard overview | No |
| `serve` + live SSE (`/api/v1/stream`) | No |
| `serve` + `/admin/security` | No |
| Audit chain (`~/.elsereno/audit.jsonl`) | No (FileWriter) |
| `vault *` | No |
| Offensive verbs (write / exploit / harvest / dial) | No |
| **Paneles dashboard de findings/triage/runs** | **Sí** |
| **`/api/v1/findings` / `/runs` / `/triage`** | **Sí** |
| **`/readyz` reporte "db": "ok"** | **Sí** (sin DB reporta "skipped") |

---

## 2. Descubrimiento (defensive, build default)

### 2.1 Flujo E2E: Shodan → scope → scan → findings → report

**Caso de uso**: cliente te entrega un dominio `ejemplo.com`;
quieres saber qué servicios ICS tienen expuestos y priorizarlos.

#### 2.1.1 Inputs desde Shodan

Shodan (requiere API key con plan paid para `search`):

```sh
# Export CSV con los 500 primeros resultados de tu query guardada
shodan search --limit 500 --fields ip_str,port,product \
  'org:"ejemplo corp" port:502' > shodan-modbus.csv

# Feed directo al scanner por stdin
shodan search 'org:"ejemplo corp"' --fields ip_str,port | \
  elsereno scan --input stdin --protocol auto --run-tag "shodan-initial"
```

#### 2.1.2 Inputs desde Censys

```sh
censys search 'services.service_name: MODBUS AND org: "ejemplo corp"' \
  --index hosts --pages 10 --output json > censys-modbus.json
elsereno scan --input-file censys-modbus.json --input-type censys
```

#### 2.1.3 Inputs desde FOFA / ZoomEye / ONYPHE (v1.8 + v1.9)

Tres proveedores alternativos a Shodan/Censys, todos wired al
CLI desde v1.9 con `--input <provider>:<query>` +
`--api-creds-file <path>`:

```sh
# ejemplo FOFA (fofa.info) — fuerte cobertura APAC
elsereno scan \
  --input fofa:'protocol="iax2" && country="ES"' \
  --api-creds-file ~/.elsereno/api-creds.yaml \
  --output-format ndjson --output findings.ndjson

# ejemplo ZoomEye (zoomeye.org) — API-KEY header auth
elsereno scan \
  --input zoomeye:'app:"Asterisk"' \
  --api-creds-file ~/.elsereno/api-creds.yaml

# ejemplo ONYPHE (onyphe.io) — OQL query syntax, v1.9+
elsereno scan \
  --input onyphe:'category:datascan product:freepbx' \
  --api-creds-file ~/.elsereno/api-creds.yaml
```

El fichero `~/.elsereno/api-creds.yaml` (obligatorio 0600):

```yaml
shodan:
  key: <shodan-api-key>
censys:
  id: <censys-api-id>
  secret: <censys-api-secret>
fofa:
  email: <fofa-email>
  key: <fofa-api-key>
zoomeye:
  key: <zoomeye-api-key>
onyphe:
  key: <onyphe-api-key>
```

El loader enforce 0600 al leer (cualquier fichero con bits de
grupo / mundo se rechaza con `chmod 600 <path>` de sugerencia)
y `KnownFields(true)` rechaza typos en las claves al parse.

Para uso programático (librería Go, sin CLI):

```go
import "local/elsereno/internal/inputs/fofa"

c, _ := fofa.New("tu-email@dominio.com", "<api-key>", 1) // 1 rps
targets, err := c.Search(ctx, `protocol="iax2"`, 100)
// targets[] es []core.Target → pipeable al scanner via stdin
```

#### 2.1.4 Inputs desde nmap XML

```sh
nmap -sS -p 102,502,1911,2404,4840,5094,10001,20000,44818,47808 \
     -oX nmap-ics.xml ejemplo.com

elsereno scan --input-file nmap-ics.xml --input-type nmapxml \
              --concurrency 50 --rate 200 --out-ndjson findings.ndjson
```

#### 2.1.5 Inputs desde stdin / lista plana

```sh
# Un "host:port" por línea
printf '10.0.0.5:502\n10.0.0.6:102\n10.0.0.7:44818\n' | \
  elsereno scan --input stdin

# O una lista en fichero
elsereno scan --input-file targets.txt
```

#### 2.1.6 Aplicar scope (filtro de sanidad previo a toda acción)

```yaml
# scope.yaml — SIEMPRE carga un scope antes de scans grandes
version: 1
ranges:
  - cidr: 10.0.0.0/16
  - cidr: 203.0.113.0/24
ports:
  allow: [102, 502, 1911, 2404, 4840, 5094, 10001, 20000, 44818, 47808]
  deny: []
protocols:
  allow: [modbus, s7, enip, bacnet, dnp3, iec104, hartip, fox, atg, opcua]
  deny: [atmodem, xot]
bind:
  allow: ["127.0.0.1", "::1"]
dial:
  blocked_numbers:
    - "555"          # prefijos prohibidos
    - "01189998819991197253"
canary:
  enabled: true
  alert_webhook: "https://canary.internal/hook"
```

Uso:

```sh
elsereno scan --scope scope.yaml --input-file targets.txt
elsereno dial validate --number "+34 91 123 4567" --scope scope.yaml
```

Un target fuera del scope **no se prueba** y queda auditéado con
`scope_applied` + `decision:denied`.

#### 2.1.7 Outputs + reporting

Cinco formatos cubren los casos habituales:

```sh
# NDJSON (máquina)
elsereno scan --input-file t.txt --out-ndjson findings.ndjson

# CSV (SOC analyst)
elsereno scan --input-file t.txt --out-csv findings.csv

# HTML (operator-friendly, dark-mode, per-protocol)
elsereno scan --input-file t.txt --out-html findings.html

# CEF / Syslog (SIEM integration)
elsereno scan --input-file t.txt --syslog udp://siem.internal:514
elsereno scan --input-file t.txt --cef-file findings.cef

# Webhook genérico (HMAC-SHA256 firmado)
elsereno scan --input-file t.txt \
  --webhook-url https://ops.example/hook \
  --webhook-secret-file ~/.elsereno/wh.pp
```

### 2.2 Dashboard SSE en vivo (v1.1+)

Mientras corre un scan grande, conecta un operador en el
navegador a `http://127.0.0.1:8787` para ver los findings
llegar en tiempo real via `/api/v1/stream` (EventSource).

El feed live tambén recibe:
- `run_start` / `run_end` — lifecycle de runs
- `finding` — cada hallazgo scored
- `audit` — entradas de la cadena hash (cross-proceso via tail)

---

## 3. Fingerprint por protocolo

Cada plugin tiene una descripción + puerto well-known:

**17 plugins en el build por defecto** (v1.8+). Cada uno tiene
una descripción + puerto well-known:

| Plugin    | Puerto       | Lo que hace |
|-----------|--------------|-------------|
| modbus    | 502/tcp      | Read-Holding-Regs + Read-Device-Identification |
| s7        | 102/tcp      | TPKT/COTP + ROSCTR=0x01 Setup Comm |
| enip      | 44818/tcp    | ListIdentity (CIP UCMM) |
| bacnet    | 47808/udp    | Who-Is (APDU broadcast) |
| dnp3      | 20000/tcp    | Read Class 0 (link-layer + APDU) |
| iec104    | 2404/tcp     | TESTFR/STARTDT (APCI U-format) |
| hartip    | 5094/tcp     | Session-Initiate |
| fox       | 1911/4911    | Banner grab "fox a" + "fox.version" |
| atg       | 10001/tcp    | `<SOH>I20100<CR>` (Veeder-Root info query) |
| opcua     | 4840/tcp     | HEL Hello → clasifica ACK/ERR/non-UA |
| xot       | 1998/tcp     | X.25 CALL REQUEST (RFC 1613) |
| atmodem   | serial/TCP   | AT+CMEE query + banner parse |
| **sip**   | 5060/udp+tcp | OPTIONS → 15-vendor PBX matcher (Asterisk/FreePBX/3CX/…) |
| **iax2**  | 4569/udp     | RFC 5456 NEW → subclase ACCEPT/AUTHREQ/REJECT |
| **pbxhttp** | 443 (+80/8080/8088/5001/…) | HTTP admin-UI fingerprint, 15 brands |
| **cwmp**  | 7547/tcp     | TR-069 ACS Inform → 15 ACS vendor fingerprints |
| banner    | 21/22/23/80  | TCP banner grab genérico (fallback) |

Los cuatro plugins en negrita se añadieron en v1.3 (PBX
discovery) y v1.4 (CWMP / TR-069).

### 3.1 Modbus

```sh
# Fingerprint + scoring
elsereno scan --input stdin <<< "10.0.0.5:502"

# Ver qué protocolo se detectó y por qué
elsereno why --finding-id <uuid>

# Explicar cómo se calcula el score
elsereno explain
```

### 3.2 Siemens S7 (102)

```sh
elsereno scan --protocol s7 --input stdin <<< "10.0.0.6:102"

# S7 responde con ID + firmware en la Setup Comm response.
# ElSereno extrae device family + firmware → factor `cve_exposure`
# sube si el firmware está en nuestra tabla de CVEs.
```

### 3.3 EtherNet/IP

```sh
elsereno scan --protocol enip --input stdin <<< "10.0.0.7:44818"

# ListIdentity saca VendorID, DeviceType, SerialNumber, ProductName.
# Si el target es Rockwell / Omron / Allen-Bradley → `protocol_risk` alto.
```

### 3.4 BACnet/IP (UDP)

```sh
elsereno scan --protocol bacnet --input stdin <<< "10.0.0.8:47808"

# Who-Is es broadcast UDP. El scanner aguanta ElayedResponseReady
# I-Am del device y extrae DeviceObject instance.
```

### 3.5 DNP3

```sh
elsereno scan --protocol dnp3 --input stdin <<< "10.0.0.9:20000"

# Read Class 0 es la consulta canónica. Respuesta con IIN2 bits
# identifica el device state (restart, need-time, class-data).
```

### 3.6 IEC 60870-5-104

```sh
elsereno scan --protocol iec104 --input stdin <<< "10.0.0.10:2404"

# STARTDT activate / TESTFR. El servidor responde con STARTDT
# confirm si acepta comandos (power-grid RTUs típicamente).
```

### 3.7 HART-IP

```sh
elsereno scan --protocol hartip --input stdin <<< "10.0.0.11:5094"

# Session Initiate. Respuesta revela si el gateway HART-IP está
# activo. El fingerprint no va más allá — las commands HART
# viven dentro de TokenPassPDU y necesitan sesión autenticada.
```

### 3.8 Niagara Fox (BMS)

```sh
elsereno scan --protocol fox --input stdin <<< "10.0.0.12:1911"

# El server envía una línea "fox a 0 -1 fox hello\n{fox.version=4.11.0}"
# en el connect. ElSereno captura eso como finding evidence.
```

### 3.9 ATG Veeder-Root (surtidores)

```sh
elsereno scan --protocol atg --input stdin <<< "10.0.0.13:10001"

# <SOH>I20100<CR> pide "In-tank inventory". Respuesta TLS-350
# comienza con "I20100\r\n" + data. Si el operador nunca
# cerró el puerto a Internet, esto es un hallazgo CRITICAL.
```

### 3.10 OPC UA (v1.1+)

```sh
elsereno scan --protocol opcua --input stdin <<< "10.0.0.14:4840"

# HEL con endpoint URL sintético. El server responde con:
#  - ACK → UA confirmado
#  - ERR → también UA confirmado (server rechazó el endpoint)
#  - bytes non-UA → posible HTTPS u otro servicio en 4840
```

### 3.11 XOT (X.25 sobre TCP, RFC 1613)

```sh
elsereno scan --protocol xot --input stdin <<< "10.0.0.15:1998"

# CALL REQUEST. Respuesta CALL ACCEPTED → XOT vivo. Más allá,
# ElSereno tiene un REPL (v1.2+) para send/clear/data manual.
```

### 3.12 AT modems (serial + TCP reverse-proxy)

```sh
# Probe TCP (muchos modem-banks exponen AT por telnet)
elsereno scan --protocol atmodem --input stdin <<< "10.0.0.16:23"

# Serial local (con CAP_NET_RAW o similar)
elsereno scan --protocol atmodem --input stdin <<< "/dev/ttyUSB0"
```

### 3.13 Banner genérico

```sh
# Catch-all: puerto desconocido, snaga banner, aplica diccionario
elsereno scan --protocol banner --input stdin <<< "10.0.0.20:2323"
```

### 3.14 SIP / PBX discovery (v1.3+)

```sh
# OPTIONS probe a 5060 UDP (por defecto) o TCP
elsereno scan --protocol sip --input stdin <<< "pbx.ejemplo.com:5060"

# Identifica 15 marcas desde Server / User-Agent / Allow headers:
#   Asterisk / FreePBX / 3CX / Cisco UCM / Cisco SIP Gateway /
#   Mitel (+ ShoreTel) / Avaya (+ IP Office) / Yeastar /
#   Grandstream / Fanvil / Yealink / Kamailio / OpenSIPS /
#   FreeSWITCH / SER.
# Scoring tiers: 90 attack-ripe (Asterisk/FreePBX/3CX);
# 85 enterprise (Cisco UCM / Avaya / Mitel); 80 SOHO (Yeastar /
# Grandstream / Fanvil / Yealink); 75 proxy/gateway;
# 70 SIP-unknown-vendor.
#
# `auth_state` baja a 50 si el servidor responde 401 Unauthorized
# con Digest challenge.
```

### 3.15 IAX2 — Asterisk binary protocol (v1.3+)

```sh
# NEW frame → clasifica la respuesta por subclase
elsereno scan --protocol iax2 --input stdin <<< "pbx.ejemplo.com:4569"

# Subclases que confirman IAX2 (protocol_risk=90, Asterisk-
# specific PBX disclosure):
#   ACCEPT  — el remote aceptó nuestra call (se envía HANGUP
#             inmediatamente para no dejar dialog colgado)
#   AUTHREQ — pide auth (auth_state baja a 50)
#   REJECT  — aceptó la llegada pero rehúsa
#   HANGUP  — cerró al vuelo
#   PING / PONG / REG* — todos confirman IAX2
#
# Mini-frames (audio) y frames no-IAX se descartan; bytes HTTP
# que coincidan con mini-frame-encoding se filtran por length
# sanity guard (real mini-frames son exactamente 4 bytes).
```

### 3.16 PBX HTTP admin-UI (v1.3+)

```sh
# Probe a la admin web (HTTPS por defecto, self-signed tolerado)
elsereno scan --protocol pbxhttp --input stdin <<< "pbx.ejemplo.com:443"

# También funciona contra puertos comunes de admin alternativos:
#   80 / 8080 / 8088 / 5001 / 8443 / 411 (Avaya IP Office)
# El plugin acepta un path alternativo vía config (por defecto "/"):
#   /admin/config.php  → FreePBX
#   /webclient/        → 3CX
#   /ccmadmin/login.do → Cisco UCM
#
# Reconoce 15 plataformas PBX vía response Server / <title> /
# body: FreePBX, PBXact (Sangoma), 3CX, Yeastar (+ NeoGate +
# Linkus), Cisco UCM, Avaya (IP Office / Aura / Communication
# Manager), Mitel (+ ShoreTel + MiCollab), Grandstream (+ UCM6
# + GXP + GXW), Fanvil, Yealink (+ SIP-T), Asterisk HTTP
# Manager, Switchvox (Digium), Elastix, FreeSWITCH.
#
# Heurística "PBX-likely": cuando ningún brand matchea pero el
# body menciona pbx / phone system / sip server / voip admin /
# extension → protocol_risk sube a 70 para que el finding no
# pase desapercibido.
#
# Default: InsecureSkipVerify=true — PBX default installs
# shippean certificados self-signed siempre; la alternativa
# sería no poder fingerprintear el 80 % de los PBXes en
# producción. El probe NO transmite credenciales, solo lee la
# página de login.
```

### 3.17 CWMP / TR-069 (v1.4+)

```sh
# ACS Inform probe a 7547/tcp
elsereno scan --protocol cwmp --input stdin <<< "acs.ejemplo.com:7547"

# Reconoce 15 plataformas ACS (Auto-Configuration Servers):
#   GenieACS (open source) / LibreACS / EasyCwmp / OpenACS /
#   Axiros ACS / Device Cloud (Digi) / Incognito / Motive /
#   Netopia ACS / Broadcom ACS / Ericsson (Ericsson EDGE) /
#   ZTE ACS / Alcatel-Lucent Motive / CommScope Arris / etc.
#
# TR-069 es el protocolo estándar de gestión remota de CPE
# (Customer Premises Equipment — routers, ONTs, STBs...).
# Un ACS público es una superficie enorme: una RCE en el ACS
# da control remoto sobre MILES de dispositivos end-user. De
# ahí el protocol_risk alto por defecto.
```

---

## 4. Scoring + triage

```sh
# Explica los 6 factores (ADR-006) y sus pesos
elsereno explain

# Mostrar el YAML embebido (pesos + umbrales)
elsereno scoring show

# Triage: agrupa findings por quick-win / strategic / routine
elsereno triage --run <uuid>
```

Los pesos por defecto:
- `protocol_risk` 25 %
- `exposure` 20 %
- `auth_state` 20 %
- `capability` 15 %
- `impact_class` 10 %
- `cve_exposure` 10 %

Severity thresholds: critical ≥ 80, high ≥ 60, medium ≥ 40, low ≥ 20.

---

## 5. API HTTP

Endpoints de lectura (default build):

```sh
# Lista de plugins registrados
curl http://127.0.0.1:8787/api/v1/plugins | jq

# Pesos de scoring en memoria
curl http://127.0.0.1:8787/api/v1/scoring | jq

# Salud / readiness
curl http://127.0.0.1:8787/api/v1/health
curl http://127.0.0.1:8787/readyz   # 503 si la DB está caída

# OpenAPI spec (código como fuente de verdad)
curl http://127.0.0.1:8787/api/v1/openapi.yaml > openapi.yaml

# SSE live feed (v1.1+)
curl -N http://127.0.0.1:8787/api/v1/stream

# Paneles DB (v1.2+; requiere DATABASE_URL)
curl 'http://127.0.0.1:8787/api/v1/findings?severity=high&limit=50' | jq
curl 'http://127.0.0.1:8787/api/v1/runs?limit=20' | jq
curl http://127.0.0.1:8787/api/v1/triage | jq
```

Panel admin + self-audit:

```
http://127.0.0.1:8787/admin/security
```

Muestra todo el estado de controles de seguridad (vault,
audit chain, CSRF, redaction, subprocess allowlist, scope,
write-ban por protocolo, sandbox seccomp, canary webhook,
backup cifrado).

---

## 6. Casos ofensivos (build `-tags offensive`)

**Requisitos**:
1. Binario construido con `-tags offensive` (release: `elsereno-offensive`).
2. Vault desbloqueado (para derivar tokens).
3. Triple confirmación: `--accept-writes`, `--confirm-target`, `--confirm-token`.
4. (Si dial) `--dial-allowed` y números > 3 dígitos.

### 6.1 Modbus write — dos modos

Modbus es el único plugin ofensivo con dos modos de operación
porque su CLI original (v1.2) era per-request, no per-session:

#### 6.1.1 Per-request (v1.2, todavía suportado)

```sh
# Paso 1: dry-run (calcula token esperado)
elsereno-offensive write modbus dry-run \
  --target 10.0.0.5:502 --unit 1 --address 100 --value 1234

# Output:
#   Category:     write
#   Protocol:     modbus
#   Operation:    write_single_register
#   PayloadHash:  a1b2c3…
#   Token:        9f8e7d… (HMAC sobre mutation con vault key)

# Paso 2: envío real con los tres flags
elsereno-offensive write modbus send \
  --target 10.0.0.5:502 --unit 1 --address 100 --value 1234 \
  --accept-writes \
  --confirm-target 10.0.0.5:502 \
  --confirm-token 9f8e7d… \
  --vault-passphrase-file ~/.elsereno/dev.pp

# La fila de audit queda en ~/.elsereno/audit.jsonl
elsereno audit verify-file
```

#### 6.1.2 Proxy-session (v1.9+, simétrico con sip/iax2/pbxhttp/opcua/bacnet)

```sh
# Dry-run: genera el confirm-token para una sesión de proxy
# listen con allowlist de function-codes
elsereno-offensive write modbus proxy-dry-run \
  --target 10.0.0.5:502 \
  --function 6 --function 16 \
  --vault-passphrase-file ~/.elsereno/dev.pp \
  --emit-allow-file /etc/elsereno/modbus-gate.yaml

# Lanzar el proxy con el YAML
elsereno-offensive proxy listen \
  --allow-file /etc/elsereno/modbus-gate.yaml \
  --listen 127.0.0.1:15020 \
  --accept-writes --confirm-target 10.0.0.5:502 \
  --confirm-token <hex> --vault-passphrase-file ~/.elsereno/dev.pp
```

Opcionalmente en el dry-run puedes endurecer con `--unit N`,
`--address-from N`, `--address-to N`. Atención: esa
combinación NO es compatible con `--emit-allow-file` porque el
schema YAML hoy solo persiste `functions:` (unit + address-
range tightening llega en v1.10). Si usas esos flags, pasa el
gate al proxy vía flags directos en lugar de `--allow-file`.

### 6.2 Exploit CVE (catálogo reducido)

```sh
# Ver CVEs disponibles
elsereno-offensive exploit list

# CVE-2015-5374 (Siemens Simatic DoS via malformed PROFINET)
# CVE-2019-10953 (Rockwell ControlLogix Denial by ENIP fragment)

elsereno-offensive exploit show cve-2015-5374
elsereno-offensive exploit dry-run --cve cve-2015-5374 --target 10.0.0.6:102

elsereno-offensive exploit run \
  --cve cve-2015-5374 --target 10.0.0.6:102 --proto udp \
  --accept-writes --confirm-target 10.0.0.6:102 --confirm-token … \
  --vault-passphrase-file ~/.elsereno/dev.pp
```

### 6.3 Harvest (descubrir credenciales débiles)

Probers: Telnet, FTP, HTTP-Basic, SNMPv1/v2c (community strings).

```sh
# Harvest contra una lista de objetivos, guarda hallazgos en vault
elsereno-offensive harvest \
  --targets harvest-list.txt \
  --probers telnet,ftp,http-basic,snmp \
  --accept-writes --confirm-target harvest-list.txt --confirm-token … \
  --vault-passphrase-file ~/.elsereno/dev.pp

# Ver credenciales descubiertas (con redacción si TTY)
elsereno-offensive creds list
elsereno-offensive creds show --name cisco-snmp-1 --reveal   # registra token_reveal en audit
```

### 6.4 Dial individual (un número)

```sh
# Validación sin dialar (gate: ≤3 dígitos + scope.blocked_numbers)
elsereno-offensive dial validate --number "+34 91 123 4567"

# Batch wardial (v1.1 chunk 8) — clasifica + audita cada número
cat > nums.txt << 'EOF'
# target list
+34 91 123 4567
+34 91 987 6543
# números peligrosos — el guard los refusa
112
555 1234
EOF

elsereno-offensive dial batch \
  --numbers-file nums.txt --scope scope.yaml --disposition preview

# Output:
#   wardial batch — 4 numbers classified:
#     allow:   2
#     short:   1 (≤3-digit hard block)
#     blocked: 1 (scope.blocked_numbers)
#   audit chain appended to: ~/.elsereno/audit.jsonl
```

### 6.5 Proxy write-gated (v1.5+ — CLI `proxy listen`)

Desde v1.5.0 todos los write-gates son ejecutables inline con
un único verbo. Soporta **6 plugins**: modbus, opcua, sip,
iax2, pbxhttp, bacnet.

#### 6.5.1 Generar allow-file YAML + confirm-token (v1.7+ emit)

El patrón canónico es `write <plugin> dry-run --emit-allow-file`:
genera el YAML Y el confirm-token en una sola llamada.

```sh
# SIP — permitir sólo INVITE + REGISTER
elsereno-offensive write sip dry-run \
  --target pbx.ejemplo.com:5060 \
  --method INVITE --method REGISTER \
  --vault-passphrase-file ~/.elsereno/vault.pp \
  --emit-allow-file /etc/elsereno/sip-gate.yaml

# Output:
#   Protocol:     sip
#   Target:       pbx.ejemplo.com:5060
#   Allowed:      INVITE, REGISTER
#   Always-safe:  OPTIONS, ACK, BYE, CANCEL, PRACK
#   PayloadHash:  0faed99d…
#   ConfirmToken: <hex-de-32-bytes>   ← para el --confirm-token del proxy
#
#   allow-file written to: /etc/elsereno/sip-gate.yaml (0600)
#   next: elsereno proxy listen --allow-file /etc/elsereno/sip-gate.yaml --accept-writes ...
```

Dry-runs disponibles:
- `write sip dry-run --target H:P --method <M>…`
- `write iax2 dry-run --target H:P --subclass <S>…`
  (subclases gated: NEW / REGREQ / AUTHREP / ACCEPT)
- `write pbxhttp dry-run --target H:P --allow METHOD:/path`
- `write opcua dry-run --target H:P --service <N> [--node-id ns=N;i=M]`
  (con `--node-id` activa el gate per-NodeId de v1.6)
- `write bacnet dry-run --target H:P --service-choice <N>`
- `write modbus dry-run …` (única que sigue el patrón viejo,
  per-request; proxy-session dry-run es v1.9 carry-over)

#### 6.5.2 Lanzar el proxy con el YAML

```sh
elsereno-offensive proxy listen \
  --allow-file /etc/elsereno/sip-gate.yaml \
  --listen 127.0.0.1:5060 \
  --accept-writes \
  --confirm-target pbx.ejemplo.com:5060 \
  --confirm-token <el-hex-del-dry-run> \
  --vault-passphrase-file ~/.elsereno/vault.pp
```

El cliente SIP (softphone, AMI, etc.) se conecta a
`127.0.0.1:5060`. El proxy:
- Siempre permite OPTIONS / ACK / BYE / CANCEL / PRACK.
- Permite INVITE + REGISTER (vienen en el allowlist).
- Rechaza cualquier otro con `SIP/2.0 405 Method Not Allowed`
  y cabecera `Allow:` listando los permitidos.
- La respuesta del upstream vuelve al cliente transparente.

#### 6.5.3 Refusal codes por protocolo

Cada gate emite un rechazo en el wire del protocolo original
(no TCP RST, para que el cliente lo parsee limpiamente):

| Plugin  | Código / estructura de rechazo |
|---------|-------------------------------|
| modbus  | Exception 0x01 ILLEGAL_FUNCTION |
| opcua   | UA ServiceFault con StatusCode `BadUserAccessDenied` (0x80100000) |
| sip     | `SIP/2.0 405 Method Not Allowed` + `Allow:` header |
| iax2    | IAX2 HANGUP frame al client's SrcCallNum |
| pbxhttp | HTTP 405 (método) o HTTP 403 (path mismatch) |
| bacnet  | BACnet Abort-PDU con reason `security-error` |

#### 6.5.4 Flags alternativos sin YAML (comandos largos)

Si prefieres no usar `--allow-file`, todos los flags están en
la CLI directa:

```sh
# equivalente al ejemplo SIP de arriba
elsereno-offensive proxy listen \
  --plugin sip \
  --target pbx.ejemplo.com:5060 \
  --method INVITE --method REGISTER \
  --listen 127.0.0.1:5060 \
  --accept-writes --confirm-target pbx.ejemplo.com:5060 \
  --confirm-token <hex> --vault-passphrase-file ~/.elsereno/vault.pp
```

#### 6.5.5 SIP INVITE destination prefix allowlist (v1.9+)

La gate SIP método-nivel de v1.4 dejaba pasar cualquier INVITE
mientras el método estuviera permitido. v1.9 añade una
segunda capa opcional: allowlist de prefijos en el URI de
destino. Caso de uso típico: operator que corre ElSereno como
trunk SIP entre un PBX tenant y un upstream carrier y quiere
permitir solo llamadas a ciertos prefijos E.164 (bloqueando
+900 premium-rate, +883 satellite, etc.).

```sh
# dry-run: permite INVITE + REGISTER, pero sólo a +34 / +44
elsereno-offensive write sip dry-run \
  --target pbx.ejemplo.com:5060 \
  --method INVITE --method REGISTER \
  --to-prefix "+34" --to-prefix "+44" \
  --vault-passphrase-file ~/.elsereno/dev.pp \
  --emit-allow-file /etc/elsereno/sip-gate.yaml

# Output:
#   Protocol:     sip
#   Target:       pbx.ejemplo.com:5060
#   Allowed:      INVITE, REGISTER
#   Always-safe:  OPTIONS, ACK, BYE, CANCEL, PRACK
#   ToPrefixes:   +34, +44
#   PayloadHash:  ...
#   ConfirmToken: <hex>
```

YAML emitido con `to_prefixes:` estructural (round-tripeable):

```yaml
plugin: sip
target: pbx.ejemplo.com:5060
methods:
  - INVITE
  - REGISTER
to_prefixes:
  - "+34"
  - "+44"
```

Comportamiento del gate:

| Request                              | Gate verdict |
|--------------------------------------|-------------|
| `INVITE sip:+34600123@pbx`           | PASA (prefix match) |
| `INVITE sip:+44207555@pbx`           | PASA (prefix match) |
| `INVITE sip:+900555@pbx`             | REFUSED → 403 Forbidden + `X-Elsereno-Gate-Reason: INVITE destination not in To-URI prefix allowlist` |
| `INVITE sip:201@pbx` (extensión)     | REFUSED (no matchea +34 ni +44) |
| `REGISTER sip:pbx SIP/2.0`           | PASA (la allowlist de prefixes solo gatea INVITE) |
| `OPTIONS sip:pbx SIP/2.0`            | PASA (always-safe) |

Nota: la lista de prefijos solo aplica a INVITE. REGISTER,
MESSAGE, SUBSCRIBE, etc. NO se ven afectados — esos métodos
siguen con el gate método-nivel únicamente.

#### 6.5.6 SIP REGISTER AOR allowlist (v1.10+, anti-registration-hijack)

El gemelo del INVITE prefix gate: mientras ese controla **dónde**
pueden ir las llamadas, el AOR allowlist controla **quién** puede
registrar un binding para recibirlas. Sin él, si un atacante
consigue las creds SIP de `alice@pbx` (phishing, WiFi sniff,
endpoint comprometido) puede registrar a `admin@pbx` apuntando a
su IP y secuestrar las llamadas entrantes al AoR legítimo.

```sh
# dry-run: permite REGISTER pero sólo para dos AoRs concretos
elsereno-offensive write sip dry-run \
  --target pbx.ejemplo.com:5060 \
  --method REGISTER \
  --aor "sip:alice@pbx.ejemplo.com" \
  --aor "sip:bob@pbx.ejemplo.com" \
  --vault-passphrase-file ~/.elsereno/dev.pp \
  --emit-allow-file /etc/elsereno/sip-register-gate.yaml

# Output:
#   Protocol:     sip
#   Target:       pbx.ejemplo.com:5060
#   Allowed:      REGISTER
#   Always-safe:  OPTIONS, ACK, BYE, CANCEL, PRACK
#   ToPrefixes:   (none — INVITE destination not constrained)
#   AORs:         sip:alice@pbx.ejemplo.com, sip:bob@pbx.ejemplo.com
#   PayloadHash:  ...
#   ConfirmToken: <hex>
```

YAML emitido con `aors:` estructural (round-tripeable):

```yaml
plugin: sip
target: pbx.ejemplo.com:5060
methods:
  - REGISTER
aors:
  - sip:alice@pbx.ejemplo.com
  - sip:bob@pbx.ejemplo.com
```

Comportamiento del gate:

| Request                                     | Gate verdict |
|---------------------------------------------|-------------|
| `REGISTER` con `To: <sip:alice@pbx…>`       | PASA (exact AOR match) |
| `REGISTER` con `To: <sips:Alice@PBX.…>`     | PASA (canonicalise: scheme strip + host lowercase) |
| `REGISTER` con `To: <sip:admin@pbx…>`       | REFUSED → 403 + `X-Elsereno-Gate-Reason: AOR not in session allowlist (REGISTER hijack guard)` |
| `REGISTER` con `To:` vacío o malformado     | REFUSED (fail-closed) |
| `INVITE sip:+34600@carrier`                 | PASA (AOR list solo gatea REGISTER) |
| `OPTIONS sip:pbx SIP/2.0`                   | PASA (always-safe) |

Match es **exacto** (no prefix) a propósito: un attacker que pase
`alice.evil@pbx…` por tu allowlist NO debería pasar también
`alice@pbx…`. La canonicalisación:

- Strip `<...>` angle brackets
- Strip `;tag=...` URI parameters
- Strip `sip:` / `sips:` / `tel:` scheme
- Lowercase el host (el user-part preservado case-sensitive per
  RFC 3261 §19.1.1)

Se puede combinar con `--to-prefix` en el mismo dry-run — ambas
gates coexisten:

```sh
elsereno-offensive write sip dry-run \
  --target pbx.ejemplo.com:5060 \
  --method INVITE --method REGISTER \
  --to-prefix "+34" --to-prefix "+44" \
  --aor "sip:alice@pbx.ejemplo.com" \
  --vault-passphrase-file ~/.elsereno/dev.pp \
  --emit-allow-file /etc/elsereno/sip-full-gate.yaml
# INVITE gatea por prefix; REGISTER gatea por AOR; el YAML lleva
# ambos bloques.
```

#### 6.5.7 OPC UA per-NodeId (v1.6+)

El gate de OPC UA puede filtrar WriteRequests no sólo por
TypeID sino también por NodeId del primer WriteValue:

```sh
# dry-run: permite WriteRequest (673) sólo contra ns=2;i=42
elsereno-offensive write opcua dry-run \
  --target plc.ejemplo.com:4840 \
  --service 673 \
  --node-id "ns=2;i=42" \
  --vault-passphrase-file ~/.elsereno/vault.pp \
  --emit-allow-file /etc/elsereno/opcua-gate.yaml

# Comportamiento del gate:
#   WriteRequest contra ns=2;i=42        → PASA
#   WriteRequest contra ns=2;i=99        → REFUSED (ServiceFault)
#   WriteRequest con NodeId encoding raro (String/Guid/ByteString)
#   cuando AllowedNodeIDs está activo    → REFUSED (fail-closed)
#   ReadRequest contra cualquier NodeId  → PASA siempre (reads no gatean)
```

Esto es lo que cierra el caso de uso "permitir al HMI escribir
sólo a la variable de setpoint durante una ventana de cambio,
pero no a la señal de presión".

#### 6.5.8 CWMP / TR-069 RPC allowlist (v1.11+)

La gate ofensiva para ACS ↔ CPE sobre TR-069. Completa el caso
de uso que v1.4 dejó abierto (fingerprint disponible, sin
gate): operador sentado entre un ACS y su parque de CPEs
permite sólo las SOAP RPCs explícitamente allowlisted.

Las RPCs read-only + protocol-flow (GetParameterNames,
GetParameterValues, GetParameterAttributes, GetRPCMethods,
Inform/InformResponse, TransferComplete, Kicked, Fault)
**pasan siempre** — bloquearlas rompería el ciclo de registro
del CPE.

Las RPCs write-capable (SetParameterValues,
SetParameterAttributes, AddObject, DeleteObject, Reboot,
FactoryReset, Download, Upload, ScheduleInform,
ScheduleDownload, ChangeDUState, CancelTransfer) requieren
allowlist explícita.

```sh
# dry-run: permite sólo SetParameterValues + Reboot
elsereno-offensive write cwmp dry-run \
  --target acs.ejemplo.com:7547 \
  --rpc SetParameterValues --rpc Reboot \
  --vault-passphrase-file ~/.elsereno/vault.pp \
  --emit-allow-file /etc/elsereno/cwmp-gate.yaml

# Output:
#   Protocol:     cwmp
#   Target:       acs.ejemplo.com:7547
#   RPCs:         Reboot, SetParameterValues
#   Always-safe:  GetParameter{Names,Values,Attributes},
#                 GetRPCMethods, Inform{,Response},
#                 TransferComplete, Kicked, Fault (+ non-POST)
#   PayloadHash:  …
#   ConfirmToken: <hex>
```

YAML emitido:

```yaml
plugin: cwmp
target: acs.ejemplo.com:7547
rpcs:
  - Reboot
  - SetParameterValues
```

Comportamiento del gate:

| Request                                                  | Gate verdict |
|----------------------------------------------------------|-------------|
| `POST /` body = `<cwmp:GetParameterValues>…`             | PASA (always-safe) |
| `POST /` body = `<cwmp:SetParameterValues>…`             | PASA (en allowlist) |
| `POST /` body = `<cwmp:Reboot>…`                         | PASA (en allowlist) |
| `POST /` body = `<cwmp:FactoryReset/>`                   | REFUSED → SOAP Fault 9001 "Request denied" + `X-Elsereno-Gate-Reason` header |
| `POST /` body = `<cwmp:Download>…`                       | REFUSED (no en allowlist) |
| `POST /` con SOAPAction pero body vacío (keep-alive)     | PASA (no hay RPC que gatear) |
| `GET /acs/status`                                        | PASA (non-POST; passthrough) |
| `POST /` con `<soapenv:Body><cwmp:Reboot>` (namespace variant) | REFUSED (el parser reconoce soap:/soap-env:/soapenv:) |

Nombres de RPC son **case-sensitive** per TR-069 §A.4:
`SetParameterValues` ≠ `setparametervalues`. El canonicaliser
acepta prefix `cwmp:` o `cwmp-1-2:` copy-pasted de wire
captures, pero case se preserva.

La refusal se emite como HTTP 200 OK + SOAP Fault body con
FaultCode 9001 — TR-069 trata errores a nivel RPC como SOAP
Faults, no HTTP errors. Esto permite que el ACS cliente
parsee la negativa limpiamente y la muestre en su GUI como "CPE
returned fault 9001 Request denied" en lugar de un error de
transporte ambiguo.

### 6.6 Sandbox seccomp-bpf (Linux)

Todos los verbs ofensivos instalan un filtro BPF por-perfil
antes del I/O network:

- `exploit`: bloquea execve/execveat/fork/clone3/ptrace/bpf/
  init_module/unshare/mount/setns/reboot + kexec + pivot_root.
- `harvest`: exploit base + bloqueo de file mutators
  (unlink, truncate, rename, chmod, mknod, …).
- `dial`: exploit base + bloqueo de network openers
  (socket, connect, bind, listen, sendto, …).

En macOS el sandbox degrada a `Kind: unavailable` + audit
`offensive_sandbox: available=false`.

---

## 7. Detection (caso defensivo — cómo lo detecta el blue team)

El red team corre ElSereno contra tu red; qué deja en logs:

### 7.1 Firma a nivel Modbus (FC + unit + address pattern)
```
src=10.0.0.100 dst=plc.internal:502
pattern: TCP SYN + TCP PSH with Modbus MBAP header (txID incrementing)
     + FC 0x01/0x03 (read coils/regs) on unit 1, address 0
response: normal device identification (FC 0x2B / subcode 14)
```
Alerta en Suricata:
```
alert tcp $EXTERNAL_NET any -> $HOME_NET 502 ( \
  msg:"ICS Modbus read from external"; \
  flow:to_server,established; \
  content:"|00 2B 0E|"; offset:7; depth:3; \
  sid:1000001; rev:1;)
```

### 7.2 Firma a nivel OPC UA HEL
```
src=attacker dst=plc:4840
pattern: TCP PSH with bytes "HEL" at offset 0, endpoint URL
         contains "opc.tcp://" + target's own IP
```
Zeek script:
```
event tcp_packet(c: connection, is_orig: bool, flags: string, seq: count,
                 ack: count, len: count, payload: string) {
    if ( |payload| >= 3 && payload[0:3] == "HEL" && c$id$resp_p == 4840/tcp )
        NOTICE([$note=OPCUA::ProbeSeen, $conn=c]);
}
```

### 7.3 Firma a nivel Veeder-Root
```
pattern: ASCII "<SOH>I20100" o variantes "I20200", "I20300", "V20100"
response: envuelve líneas con tankID, inventory, alarm codes
```

### 7.4 Signaling de writes hostiles

- Modbus FC 5/6/15/16/22/23 desde fuentes externas al cuadro de
  HMIs → **alerta crítica**.
- S7 ROSCTR 0x01 con function_code 0x04 (PLC control → STOP) → alerta.
- DNP3 app FC 0x05/0x06 (DirectOperate) desde subnet no-master → alerta.
- IEC-104 I-frame con ASDU type 45-51 → alerta.

### 7.5 Dashboard como receptor de detection

Si tu stack envía a ElSereno (vía `syslog` output):

```sh
# Agente ICS-NIDS vuelca CEF a ElSereno
elsereno scan --input-file cef-events.csv --input-type cef \
              --out-ndjson merged.ndjson
```

---

## 8. Backup + restauración

Backup cifrado del vault + config:

```sh
# Cifrado AES-GCM con master key derivada de la passphrase
elsereno backup create --out backup-2026-04-22.elsb

# Restore
elsereno backup restore --in backup-2026-04-22.elsb
```

Audit chain:
```sh
elsereno audit verify-file       # valida ~/.elsereno/audit.jsonl
elsereno audit export --out audit.jsonl.asc   # firma con GPG
```

---

## 9. Arquitectura (bird's-eye)

```
        ┌──────────────┐       ┌──────────────┐
        │  Input       │       │  Output      │
        │ shodan/censys│       │ ndjson/csv   │
        │  nmapxml/txt │       │ html/cef     │
        └──────┬───────┘       │ syslog/webhk │
               │               │ jira/ghissue │
               ▼               └──────┬───────┘
        ┌──────────────┐              ▲
        │   Scanner    │              │
        │  concurrency │              │
        │  rate + retry│              │
        └──────┬───────┘              │
               │                      │
               ▼                      │
        ┌──────────────┐  ┌──────────────┐
        │  Protocol    │  │  Scoring     │
        │  Plugin *13  │─▶│  factors×6   │
        └──────┬───────┘  └──────┬───────┘
               │                 │
               ▼                 ▼
        ┌──────────────┐  ┌──────────────┐
        │  Findings    │  │  Audit chain │
        │  pgx.CopyFrom│  │ JCS+SHA256   │
        └──────┬───────┘  └──────┬───────┘
               │                 │
               └────────┬────────┘
                        ▼
                 ┌──────────────┐
                 │  Dashboard   │
                 │  SSE stream  │
                 │ /api/v1/*    │
                 └──────────────┘
```

---

## 10. Troubleshooting frecuente

### 10.1 `vault: bad passphrase`
Reintentarlo; no hay recuperación (por diseño ADR-018). Para
instalación en máquina nueva: `vault init` de cero + reimportar
credenciales desde backup cifrado.

### 10.2 `serve: CSRF key: HKDF failed`
El vault no está desbloqueado. `elsereno vault unlock` antes.

### 10.3 Dashboard sin estilos
Indica que tu navegador está bloqueando el inline `<style>` por
CSP. Desde v1.1 chunk 4a (y v1.2 en `/admin/security`) el nonce
está cableado. Si ves esto, tu binario es viejo — actualiza.

### 10.4 `/readyz` devuelve 503
Postgres caído. `docker compose ps db` para ver el estado, o
desconfigura `DATABASE_URL` si quieres correr sin DB.

### 10.5 `audit: ErrChainBroken`
Alguien (o algo) tocó el fichero `~/.elsereno/audit.jsonl`. Esto
es grave: la cadena hash ya no valida. Procedimiento:
1. `cp ~/.elsereno/audit.jsonl audit-corrupt.jsonl.bak`
2. Investigar quién modificó (mtime, zfs snapshots, etc.)
3. Si el operador quiere seguir: `elsereno audit rebase` inserta
   un rebase marker + reinicia la cadena. La corruption queda
   auditéada de forma explícita (no oculta).

---

## 11. Enlaces

- Repo: https://github.com/RobinR00T/elSereno
- Releases: https://github.com/RobinR00T/elSereno/releases
- SECURITY.md: políticas de vulnerability disclosure
- LEGAL.md: condiciones de uso + dual-use warning
- NON-GOALS.md: qué NO hace ElSereno (para evitar malentendidos)
- ADRs: .context/decisions/ en el repo (042 = seccomp, 040 = write-gate, 039 = triple-confirm)

---
