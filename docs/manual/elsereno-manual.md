# ElSereno — Manual de casos de uso

*Para operadores de seguridad OT/ICS que hacen descubrimiento,
fingerprint y test autorizado de protocolos industriales legacy.*

**Versión del manual**: v1.2 · 2026-04-22
**Compatible con binario**: v1.1.0+ (OPC UA) y v1.2.0+ (paneles DB + gates por protocolo)

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

### 1.1 Instalación desde release firmada

```sh
# Descargar la última versión + bundle cosign
VERSION=1.1.0
OS=darwin          # o linux
ARCH=arm64         # o amd64
BASE="https://github.com/RobinR00T/elSereno/releases/download/v${VERSION}"

curl -fLo "elsereno_${VERSION}.tar.gz" "${BASE}/elsereno_${VERSION}_${OS}_${ARCH}.tar.gz"
curl -fLo checksums.txt         "${BASE}/checksums.txt"
curl -fLo checksums.txt.bundle  "${BASE}/checksums.txt.bundle"

# Integridad sha256 + firma cosign keyless
shasum -a 256 -c checksums.txt --ignore-missing
cosign verify-blob \
  --bundle checksums.txt.bundle \
  --certificate-identity-regexp 'https://github.com/RobinR00T/elSereno/.*' \
  --certificate-oidc-issuer     'https://token.actions.githubusercontent.com' \
  checksums.txt

tar xzf "elsereno_${VERSION}.tar.gz"
./elsereno version
```

### 1.2 Instalación por docker (multi-arch + SBOM)

```sh
docker pull ghcr.io/robinr00t/elsereno:latest

# Verifica la firma del manifiesto
cosign verify ghcr.io/robinr00t/elsereno:latest \
  --certificate-identity-regexp 'https://github.com/RobinR00T/elSereno/.*' \
  --certificate-oidc-issuer     'https://token.actions.githubusercontent.com'

# Descarga + cuenta componentes del SBOM
cosign download sbom ghcr.io/robinr00t/elsereno:latest | jq '.components | length'
```

### 1.3 Primer arranque — vault + dashboard

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

### 1.4 Dashboard con Postgres (opcional, v1.2+)

Sin `$DATABASE_URL`, los paneles de findings/triage/runs
responden 503 y la UI muestra "backend unavailable". Los paneles
overview / plugins / live-feed / security siguen funcionando
100% sin BD — la BD es sólo para historia persistida.

#### 1.4.1 Con el script helper (`scripts/dev-db.sh`)

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

#### 1.4.2 Manual (sin script)

Si prefieres no usar el script:

```sh
docker compose -f docker-compose.dev.yml up -d db
export DATABASE_URL="postgres://elsereno@127.0.0.1:5433/elsereno?sslmode=disable"
elsereno db migrate up
elsereno serve
```

#### 1.4.3 Matriz "¿necesito BD?"

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

#### 2.1.3 Inputs desde nmap XML

```sh
nmap -sS -p 102,502,1911,2404,4840,5094,10001,20000,44818,47808 \
     -oX nmap-ics.xml ejemplo.com

elsereno scan --input-file nmap-ics.xml --input-type nmapxml \
              --concurrency 50 --rate 200 --out-ndjson findings.ndjson
```

#### 2.1.4 Inputs desde stdin / lista plana

```sh
# Un "host:port" por línea
printf '10.0.0.5:502\n10.0.0.6:102\n10.0.0.7:44818\n' | \
  elsereno scan --input stdin

# O una lista en fichero
elsereno scan --input-file targets.txt
```

#### 2.1.5 Aplicar scope (filtro de sanidad previo a toda acción)

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

#### 2.1.6 Outputs + reporting

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

| Plugin    | Puerto      | Lo que hace |
|-----------|-------------|-------------|
| modbus    | 502         | Read-Holding-Regs + Read-Device-Identification |
| s7        | 102         | TPKT/COTP + ROSCTR=0x01 Setup Comm |
| enip      | 44818       | ListIdentity (CIP UCMM) |
| bacnet    | 47808/udp   | Who-Is (APDU broadcast) |
| dnp3      | 20000       | Read Class 0 (link-layer + APDU) |
| iec104    | 2404        | TESTFR/STARTDT (APCI U-format) |
| hartip    | 5094        | Session-Initiate |
| fox       | 1911/4911   | Banner grab "fox a" + "fox.version" |
| atg       | 10001       | `<SOH>I20100<CR>` (Veeder-Root info query) |
| opcua     | 4840        | HEL Hello → clasifica ACK/ERR/non-UA |
| xot       | 1998        | X.25 CALL REQUEST (RFC 1613) |
| atmodem   | serial/TCP  | AT+CMEE query + banner parse |
| banner    | 21/22/23/80 | TCP banner grab genérico |

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

### 6.1 Modbus write

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

### 6.5 Proxy write-gated (v1.1 + v1.2)

Para auditorías supervisadas donde el operador quiere pasar por
un MITM controlado (ejemplo: permitir sólo un FC modbus
concreto desde un HMI durante una ventana de cambio):

```sh
# Ejemplo hipotético de pipeline (la CLI `proxy serve` queda
# para v1.2 chunk 6). En v1.1/v1.2 la infra está lista; el verbo
# público CLI llega en el close del ciclo v1.2).
# Una vez enganchado el `WriteGatedHandler`:
#   - HEL/OPN/CLO (OPC UA) pasan transparentes
#   - MSG con Write service TypeID 673 refused si no está en allowlist
#   - El refusal es una UA ServiceFault con status 0x80100000
```

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
