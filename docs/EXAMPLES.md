# Ejemplos prácticos

Una receta por feature, con el comando y la salida que da de verdad. Toda
la salida de esta página sale de `examples/run-examples.sh`, ejecutado el
18-10-2026 en macOS arm64 con el binario de `main`. Las rutas del
laboratorio se acortan a `<lab>`; las horas, los IDs, las sales y el
tamaño del vault cambian en cada ejecución.

Referencia completa de cada comando: [MANUAL.md](MANUAL.md). Aquí se
enseña para qué sirve cada cosa y qué hay que mirar en la salida.

## Índice

1. [El laboratorio](#1-el-laboratorio)
2. [Primeros pasos: version, legal, doctor](#2-primeros-pasos-version-legal-doctor)
3. [Qué protocolos sabe hablar el binario](#3-qué-protocolos-sabe-hablar-el-binario)
4. [Configuración: lint, config show, fmt](#4-configuración-lint-config-show-fmt)
5. [Vault y credenciales](#5-vault-y-credenciales)
6. [Scope: a qué se puede conectar](#6-scope-a-qué-se-puede-conectar)
7. [Scan](#7-scan)
8. [Leer los findings: triage, explain, why, scoring](#8-leer-los-findings-triage-explain-why-scoring)
9. [Normas: standards](#9-normas-standards)
10. [Descubrir puertos ICS: discover](#10-descubrir-puertos-ics-discover)
11. [Sondear un solo servicio](#11-sondear-un-solo-servicio)
12. [Análisis offline de capturas](#12-análisis-offline-de-capturas)
13. [Cadena de auditoría](#13-cadena-de-auditoría)
14. [Backup y restauración](#14-backup-y-restauración)
15. [Dashboard, API y schedules](#15-dashboard-api-y-schedules)
16. [OSINT pasivo con InternetDB](#16-osint-pasivo-con-internetdb)
17. [Lo que esta página no cubre](#17-lo-que-esta-página-no-cubre)

## 1. El laboratorio

Nada de esta página toca una red ajena. Los targets son tres simuladores
del repo escuchando en loopback:

| Simulador            | Dirección        | Protocolo            |
|----------------------|------------------|----------------------|
| `simulators/modbus`  | `127.0.0.1:1502` | Modbus/TCP           |
| `simulators/opcua`   | `127.0.0.1:4840` | OPC UA (binario)     |
| `simulators/slmp`    | `127.0.0.1:5007` | MELSEC SLMP          |

Modbus va en el 1502 porque un proceso sin privilegios no puede atarse a
`127.0.0.1:502` (`bind: permission denied`). Eso importa en la receta de
`scan`: cada plugin prueba solo su puerto por defecto.

Los ficheros del laboratorio están en [`examples/`](../examples):
`targets.txt`, `scope.yaml` y `elsereno.yaml`. Para reproducirlo todo:

```bash
examples/run-examples.sh
```

O solo una receta, por el prefijo de su id (`info`, `plugins`, `config`,
`vault`, `scan`, `triage`, `standards`, `discover`, `probe`, `offline`,
`audit`, `backup`, `serve`, `api`). La receta `osint` es la única que sale
a internet y solo corre si la pides por su nombre:

```bash
examples/run-examples.sh scan
```

El script compila el binario y los simuladores, apunta `HOME` a un
directorio temporal (tu `~/.elsereno` real no se lee ni se escribe) y lo
borra todo al salir. Tarda unos 30 segundos.

## 2. Primeros pasos: version, legal, doctor

```bash
elsereno version
elsereno legal
elsereno doctor
```

`legal` imprime la política de uso: hace falta autorización escrita del
dueño de los sistemas. `doctor` comprueba el entorno:

```text
[OK]    go runtime, go1.26.10
[OK]    platform, darwin/arm64
[SKIP]  privileged scan, not root; not needed: scan and discover use ordinary TCP/UDP sockets
[SKIP]  nmap, not on PATH; optional: elsereno never runs it, --input nmap:FILE reads XML made elsewhere
[OK]    ipv6, at least one IPv6 address present
[OK]    disk, 239340 MiB free

6 checks, 0 failed
```

Los dos SKIP no impiden nada: los probes usan sockets normales, sin
root, y elsereno nunca ejecuta nmap; `--input nmap:<fichero>` lee un XML
que generaste tú con nmap en otra parte. Un binario compilado a mano dice `dev` como
versión; los de release llevan versión, commit y fecha.

## 3. Qué protocolos sabe hablar el binario

```bash
elsereno plugins list
elsereno plugins ports
```

`plugins list` da los 35 plugins del build por defecto, uno por línea,
con lo que hace cada uno. Los marcados *opt-in* (por ejemplo
`s7-exposure` o `codesys-active`) no corren en un scan salvo que los
pidas con `--plugin`. `plugins ports` es el índice inverso, puerto a
plugins:

```text
  102  [mms s7]
  443  [pbxhttp]
  502  [modbus]
  789  [redlion]
 1217  [codesys]
 1883  [mqtt]
 1911  [fox]
 1962  [pcworx]
```

## 4. Configuración: lint, config show, fmt

En [`examples/elsereno.yaml`](../examples/elsereno.yaml) solo
`scanner.max_concurrent_targets` cambia el valor por defecto (10 en vez
de 100); el resto de claves lleva su valor por defecto para enseñar
dónde va cada una.

```bash
elsereno --config elsereno.yaml config lint
elsereno lint --config elsereno.yaml --scope scope.yaml
```

```text
ok: elsereno.yaml
config: ok (elsereno.yaml)
scope:  ok (scope.yaml)
```

Una clave que no existe es un error, no un aviso. Con `web.addr` (que no
es una clave del fichero: la dirección va en `serve --addr`) sale:

```text
elsereno: config: unknown field: web.addr
```

con código de salida 78. `config show` imprime la configuración efectiva,
los valores por defecto más lo que pone el fichero, y dice de dónde la
leyó:

```text
# source: elsereno.yaml
retention:
    findings_days: 0
    evidence_days: 0
    runs_days: 0
evidence:
    max_payload_bytes: 16384
scanner:
    max_concurrent_targets: 10
    max_concurrent_per_host: 1
```

`fmt` reescribe el YAML con orden y sangría canónicos. **Se pierden los
comentarios**: la salida del fichero de ejemplo ya no lleva su cabecera.

```bash
elsereno fmt elsereno.yaml
```

```text
log:
    level: info
scanner:
    max_concurrent_per_host: 1
    max_concurrent_targets: 10
web:
    rate_limit_per_min_ip: 100
    rate_limit_per_min_token: 300
```

## 5. Vault y credenciales

El vault guarda claves de API y otros secretos cifrados con una
passphrase. La passphrase va en un fichero `0600`, nunca en la línea de
comandos ni en una variable de entorno.

```bash
umask 077
elsereno vault init --vault-passphrase-file pp
elsereno vault status
```

```text
vault created: <lab>/home/.elsereno/vault.v1.bin
vault: initialised (<lab>/home/.elsereno/vault.v1.bin)
```

`creds` lee de stdin. En un terminal pregunta la passphrase y el valor
sin eco. Por tubería lee dos líneas: primero la passphrase, después el
valor.

```bash
{ cat pp; echo lab-demo-value; } | elsereno creds store lab_demo
elsereno creds list < pp
elsereno creds show lab_demo < pp
```

```text
stored "lab_demo" in <lab>/home/.elsereno/vault.v1.bin
lab_demo                 created=2026-10-18T19:32:00Z
name:       lab_demo
created:    2026-10-18T19:32:00Z
hint: pass --reveal to print the plaintext (not in the audit chain yet)
```

`show` sin `--reveal` nunca imprime el valor. Para una clave real, por
ejemplo la de Shodan, se guarda con el nombre que espera el input
(`shodan_api_key`) y el valor no pasa nunca por el historial del shell.

## 6. Scope: a qué se puede conectar

[`examples/scope.yaml`](../examples/scope.yaml) limita el laboratorio a
loopback, a los tres puertos de los simuladores y a cinco plugins:

```yaml
version: 1
ranges:
  - cidr: 127.0.0.1/32
    note: "local lab, simulators only"
ports:
  allow: [1502, 4840, 5007]
  deny: [23]
protocols:
  allow: [modbus, opcua, slmp, melsoft, banner]
```

El scope solo se aplica si lo pasas con `--scope`; nada lo carga solo.
`targets.txt` incluye a propósito `127.0.0.1:23`, que el scope deniega:
lo verás descartado en la receta siguiente. Valídalo antes de usarlo:

```bash
elsereno lint --scope scope.yaml
```

## 7. Scan

```bash
elsereno scan --input list:targets.txt --scope scope.yaml --no-progress --output findings.ndjson
```

```text
elsereno scan: scope dropped 1 of 4 targets
elsereno scan: scope protocols leave out 27 plugins: atg, atmodem, bacnet, codesys, cwmp, dlms, dnp3, enip, finsudp, fox, gesrtp, hartip, iax2, iec104, knxip, mbustcp, mms, mqtt, opcuahttps, pbxhttp, pcworx, proconos, redlion, s7, sip, twincat, xot
scan complete: 6 findings (from 3 targets, 6 probes across 4 plugins)
```

Qué mirar:

- El scope descartó el puerto 23 antes de conectar y dejó fuera 27
  plugins. Lo dice por stderr; el fichero de findings no lo recoge.
- 6 findings, uno por línea en NDJSON. Resumidos (puerto, protocolo,
  severidad, score):

```text
5007 banner low 28
4840 banner low 28
1502 banner low 28
5007 melsoft high 67
4840 opcua high 67
5007 slmp high 77
```

- El simulador de Modbus en el 1502 solo da un finding de `banner`: el
  plugin `modbus` prueba el puerto 502, no el 1502. Para un servicio en
  un puerto no estándar, usa `fingerprint probe` (sección 11).
- El 5007 da dos findings de protocolo, `slmp` y `melsoft`, porque los
  dos plugins comparten puerto y los dos reconocen al simulador.

Una línea completa de NDJSON:

```json
{"schema":"ndjson:v1","run_id":"","target_id":"","address":"127.0.0.1","port":5007,"protocol":"banner","severity":"low","score":28,"factors":{"auth_state":50,"capability":10,"cve_exposure":0,"exposure":50,"impact_class":10,"protocol_risk":5},"created_at":"2026-10-18T19:32:40.99286Z"}
```

Los mismos targets, un solo plugin y salida CSV:

```bash
elsereno scan --input list:targets.txt --scope scope.yaml --no-progress --plugin slmp --output-format csv
```

```text
schema,run_id,target_id,address,port,protocol,severity,score,created_at
csv:v1,,,127.0.0.1,5007,slmp,high,77,2026-10-18T19:32:54.022534Z
```

`--output-format stix` da un bundle STIX 2.1. Otras entradas:
`--input nmap:<fichero>` lee una salida XML de nmap y `--input stdin`
lee targets por tubería. `--input shodan:<query>` (y censys, fofa,
zoomeye, onyphe, binaryedge) necesita `--api-creds-file`; no se ejecuta
aquí porque pide claves reales. `--input internetdb:` no necesita clave:
sección 16.

## 8. Leer los findings: triage, explain, why, scoring

`triage` agrupa los findings en cuatro cubos:

```bash
elsereno triage --from-file findings.ndjson
```

```text
quick_win: 0
strategic: 0
utility:   3
routine:   3
```

`explain` desglosa el score de un finding factor a factor y lo recalcula:

```bash
grep '"protocol":"slmp"' findings.ndjson | elsereno explain
```

```text
Factor breakdown:
  factor          sub     weight  contrib   
  auth_state      95      0.20    19.00       (known)
  capability      75      0.15    11.25       (known)
  cve_exposure    45      0.10    4.50        (known)
  exposure        75      0.20    15.00       (known)
  impact_class    75      0.10    7.50        (known)
  protocol_risk   80      0.25    20.00       (known)

recomputed: score=77 severity=high
stored severity: high
```

La suma de la columna `contrib` es el score: 19 + 11,25 + 4,5 + 15 +
7,5 + 20 = 77,25, que se redondea a 77, `high`. `scoring show` da los
pesos y los umbrales:

```bash
elsereno scoring show
```

```text
Factor weights (ADR-006):
  protocol_risk   0.25
  exposure        0.20
  auth_state      0.20
  capability      0.15
  impact_class    0.10
  cve_exposure    0.10

Severity thresholds:
  critical  score >= 80
  high      score >= 60
  medium    score >= 40
  low       score >= 20
  info      score <  20
```

`scoring example` calcula el caso con todos los factores a 50
(`score=50 severity=medium`). `why <dirección:puerto>` imprime hoy los
mismos pesos y te remite a `explain`: no lee findings guardados del
target.

```bash
elsereno scoring example
elsereno why 127.0.0.1:5007
```

## 9. Normas: standards

Qué vulnerabilidad de una norma demuestra cada protocolo:

```bash
elsereno standards --protocol modbus
```

```text
modbus
    NIST SP 800-82 r4 Table 16: Use of unsecure OT protocols
```

Sin `--protocol` lista todos; con `--json` da el catálogo entero. Los
mismos datos van en el campo `standards` de cada finding.

## 10. Descubrir puertos ICS: discover

`discover` hace un TCP connect a los puertos por defecto de todos los
plugins en un rango y dice qué responde, sin lanzar sondas de protocolo:

```bash
elsereno discover --auto 127.0.0.1/32 --scope scope.yaml
```

```text
{"address":"127.0.0.1","port":4840,"protocol_hints":["opcua"],"latency_ms":0}
{"address":"127.0.0.1","port":5007,"protocol_hints":["melsoft","slmp"],"latency_ms":0}
{"address":"127.0.0.1","port":5007,"protocol_hints":["melsoft","slmp"],"latency_ms":0}
discover: 3 responsive (host, port) pairs
```

El 1502 no aparece porque no es puerto por defecto de ningún plugin. El
5007 sale dos veces porque dos plugins lo declaran, y el total cuenta las
dos líneas. Para una lista de IPs en vez de un CIDR: `--hosts fichero`.
`--max-hosts` (256 por defecto) limita cuántas direcciones recorre.

## 11. Sondear un solo servicio

`fingerprint probe` lanza un plugin concreto contra un `host:puerto`
concreto, en cualquier puerto:

```bash
elsereno fingerprint probe --plugin modbus --target 127.0.0.1:1502
```

```text
protocol: modbus
severity: high
score:    72
factors:
  auth_state:     90
  capability:     60
  cve_exposure:   9
  exposure:       80
  impact_class:   70
  protocol_risk:  85
```

`plaintext-check` dice si el servicio va en claro:

```bash
elsereno plaintext-check --target 127.0.0.1:1502
```

```text
Reachable:   true
Transport:   cleartext (no TLS)
[!] EXPOSURE: this service carries its traffic in plaintext (SP 800-82 r4 Table 16).
```

`opcua probe-anon` intenta abrir de verdad una sesión anónima:

```bash
elsereno opcua probe-anon --target 127.0.0.1:4840
```

```text
OPC UA server:            false
Anonymous advertised:     false (policyId "")
Anonymous session opened: false
```

El simulador no es un servidor OPC UA real: contesta a cada mensaje con
una respuesta enlatada. Eso basta para que el scan lo reconozca, pero no
para abrir una sesión, y por eso todo sale `false`. Contra un servidor real con acceso anónimo, las tres líneas
dicen `true`, y `opcua probe-write` recorre después el espacio de
direcciones buscando tags escribibles.

Para un PLC Siemens, `s7 probe --target <plc>:102` lee modelo, firmware y
nivel de protección en una sola pasada, en solo lectura. El repo no trae
simulador de S7, así que aquí no hay salida.

Todos estos comandos aceptan `--scope`: un target fuera de scope se
rechaza con 77 sin conectar.

## 12. Análisis offline de capturas

Ninguna de estas recetas abre una conexión: trabajan sobre bytes que ya
tienes.

**Validar un plugin contra una respuesta capturada.** Una respuesta de
excepción Modbus (dirección no válida), en hex:

```bash
elsereno fingerprint validate --plugin modbus --hex "0001 0000 0003 01 83 02"
```

La salida es el finding que daría el plugin (`protocol: modbus`,
`severity: high`, `score: 72`). Para capturar esos bytes de un cliente
real: `fingerprint capture --listen 127.0.0.1:19999 --output resp.bin`, y
luego `fingerprint validate --file resp.bin`.

**Vigilar escrituras Modbus.** Un fichero con una trama Modbus/TCP en hex
por línea:

```text
# read holding registers (benign)
0001 0000 0006 01 03 0000 000a
# write single register: a write on the wire
0002 0000 0006 01 06 0001 00ff
# diagnostics 0x08 sub-function 0x0001: restart communications
0003 0000 0006 01 08 0001 0000
```

```bash
elsereno modbus monitor --file modbus-frames.txt
```

```text
frame 2: [medium] write_observed unit=1 fc=0x06 write fc=0x06 addr=1 value=0x00ff
frame 3: [high] dangerous_diagnostic unit=1 fc=0x08 mutating diagnostic sub-function 0x0001
processed 3 Modbus frames, 2 events
```

La lectura no da evento. La escritura sale `medium` y el reinicio de
comunicaciones, `high`. `--json` da un evento NDJSON por línea.

**GOOSE (IEC 61850).** Decodificar una trama:

```bash
elsereno goose decode --hex "010ccd010001001122334455 88b8 0001 0019 00000000 610f 830174 81010a 850101 860100 880101"
```

```text
GOOSE appid=0x0001 goID="t" gocbRef="" stNum=1 sqNum=0 test=false confRev=1 ttl=10ms
```

`goose monitor` detecta el ataque típico de subestación: una trama
inyectada con un `stNum` más alto que el del publicador real.
`scripts/demo-goose-monitor.sh` lo monta de principio a fin; su salida:

```text
frame 3: [high] stnum_jump key="t" stNum jumped 1 -> 9 (+8)
frame 4: [high] test_bit_set key="t" simulation/test bit set
frame 4: [info] state_change key="t" state change stNum 9 -> 10
processed 4 GOOSE/SV frames, 3 anomaly events
```

**PROFINET DCP.** Codificar un Identify-All y decodificar una trama:

```bash
elsereno profinet encode-identify --xid 1
elsereno profinet decode --hex fefe0500cafebabe00010006ffff00020000 --strip-l2 0
```

```text
fefe05000000000100010006ffff00020000
DCP Frame
  FrameID:      0xFEFE
  ServiceID:    0x05 (Identify)
  ServiceType:  0x00 (Request)
  XID:          0xCAFEBABE
  DataLength:   6
  Blocks: 1
    [0] Option=0xFF(All) Sub=0xFF Length=2 BlockInfo=0x0000 DataLen=0
```

## 13. Cadena de auditoría

```bash
elsereno audit verify-file
```

```text
no audit log at <lab>/home/.elsereno/audit.jsonl (nothing to verify)
```

En el laboratorio no hay entradas todavía: ni `vault init` ni
`creds store` escriben en el fichero de auditoría. En una instalación con
historial, `verify-file` recorre la cadena y falla si una entrada fue
alterada o borrada, y `audit export` la saca en NDJSON, CEF o syslog
para un SIEM. `audit verify`, `compact` y `purge`, los de la cadena en
Postgres, todavía no hacen nada: salen con 69.

## 14. Backup y restauración

```bash
elsereno backup create --out vault.bak --vault-passphrase-file pp
elsereno backup inspect --in vault.bak
mkdir restored
elsereno backup restore --in vault.bak --to restored --vault-passphrase-file pp
```

```text
wrote vault.bak (488 bytes payload, envelope version 1)
path:      vault.bak
magic:     0x454c5342 (ELSB)
version:   1
salt:      d928a4101475628079554c0d9837d51a
nonce:     dabf2d972cbca9451f155648
size:      469 bytes
mode:      0600
restored restored/vault.v1.bin (488 bytes, mode 0600)
```

`inspect` no descifra nada: lee la cabecera. `restore` necesita que el
directorio de destino exista; si no, sale con 64 (`stat restored: no
such file or directory`).

## 15. Dashboard, API y schedules

`serve` levanta el dashboard y la API. Necesita el vault; en loopback
arranca en modo dev, sin TLS ni OIDC, y el operador va en la cabecera
`X-Operator`.

```bash
elsereno serve --scan-store=memory --addr 127.0.0.1:18787 --vault-passphrase-file pp
```

```text
elsereno serve: scan-store=memory; pool=2 (jobs lost on restart)
elsereno serve: listening on 127.0.0.1:18787
elsereno serve: auth in DEV mode (X-Operator header; no OIDC)
elsereno serve: rate limits per IP 100/min (loopback exempt), per token 300/min
```

Abre `http://127.0.0.1:18787` en el navegador para el dashboard. Con
`--scan-store=memory` los scans se pierden al parar. Para escuchar fuera
de loopback hacen falta TLS, `--i-know-what-im-doing` y OIDC (MANUAL,
§2.3 y §18).

Lanzar un scan por la API y ver cómo acaba:

```bash
curl -s -X POST http://127.0.0.1:18787/api/v1/scans \
    -H "X-Operator: alice" -H "Content-Type: application/json" \
    -d '{"input":"list:/ruta/a/targets.txt","plugins":["slmp","opcua"]}'
curl -s http://127.0.0.1:18787/api/v1/scans -H "X-Operator: alice"
```

La primera llamada devuelve 202 con el scan en `queued`. Unos segundos
después, la segunda lo da `completed`, con `targets_seen: 4`,
`targets_scanned: 2`, `findings_count: 2` y `findings_by_plugin`
`{"opcua": 1, "slmp": 1}`. Por la API no se pasa scope, así que el 23
cuenta como visto, pero ni slmp ni opcua lo prueban.

Crear un schedule (201 con `next_fire_at`) y manejarlo desde la CLI:

```bash
curl -s -X POST http://127.0.0.1:18787/api/v1/schedules \
    -H "X-Operator: alice" -H "Content-Type: application/json" \
    -d '{"name":"lab-nightly","template":{"input":"list:/ruta/a/targets.txt","plugins":["slmp"]},"cron_expr":"0 2 * * *","timezone":"Europe/Madrid"}'
export ELSERENO_URL=http://127.0.0.1:18787
elsereno schedule list
elsereno schedule disable 2e361df5a56e3a71 --dry-run
elsereno schedule delete 2e361df5a56e3a71
elsereno schedule delete 2e361df5a56e3a71 --dry-run
```

```text
ID                NAME         CADENCE                         ENABLED  LAST FIRED
2e361df5a56e3a71  lab-nightly  cron=0 2 * * * (Europe/Madrid)  true     -
[dry-run] would disable schedule 2e361df5a56e3a71
elsereno: elsereno schedule delete: pass --yes to confirm (or --dry-run)
[dry-run] would DELETE 2e361df5a56e3a71
```

Las 02:00 de Madrid son las 00:00 UTC del día siguiente, que es lo que da
`next_fire_at`. `delete` sin `--yes` no borra y sale con 1. `--dry-run`
dice lo que haría sin tocar nada. `schedule export --format csv` saca
todos los schedules para un backup.

`/api/v1/findings` necesita Postgres (`--scan-store=db`). Con
`--scan-store=memory` responde `findings backend unavailable`.

La especificación OpenAPI 3.1 completa de la API:

```bash
elsereno api openapi > openapi.yaml
```

## 16. OSINT pasivo con InternetDB

Antes de tocar un equipo puedes preguntar qué sabe ya internet de él.
Shodan InternetDB responde, sin clave de API, con los puertos abiertos
que Shodan vio en una IP. ElSereno lo usa como entrada de `scan`.

**Paso 1, solo mirar.** La consulta a InternetDB es pasiva: la recibe
Shodan, no el equipo. Con `curl`:

```bash
curl -s https://internetdb.shodan.io/192.0.2.10
```

```text
{"detail":"No information available"}
```

`192.0.2.10` es una dirección reservada para documentación (RFC 5737), así
que Shodan no tiene nada y responde 404. Con una IP pública tuya, la
respuesta trae `ip`, `ports`, `hostnames`, `cpes`, `tags` y `vulns`. De
todo eso, ElSereno usa `ports`, que convierte en un target por puerto.

**Paso 2, sondear lo que Shodan vio.** Esto ya no es pasivo: `scan`
conecta a cada puerto que devuelva InternetDB. Hace falta autorización
del dueño, y conviene pasar un `--scope` con tu rango para que una IP
mal escrita no acabe en un equipo ajeno.

```bash
elsereno scan --input internetdb:192.0.2.10 --scope scope.yaml --no-progress
```

```text
elsereno: --input internetdb:192.0.2.10 gave no targets
```

Sale con 66: InternetDB no tenía puertos para esa IP, así que no hay nada
que sondear. Con datos, la salida es la de la sección 7.

Tres formas de pasar direcciones:

| Entrada                   | Qué hace                                     |
|---------------------------|----------------------------------------------|
| `internetdb:<ip>`         | Una IP (IPv6 también, con o sin corchetes).  |
| `internetdb:file:ips.txt` | Una IP por línea; `#` empieza un comentario. |
| `internetdb:-`            | Una IP por línea desde stdin.                |

No acepta rangos. Un CIDR es un error de datos, con salida 65:

```text
elsereno: internetdb: query must be a parseable IP address: "192.0.2.0/24"
```

ElSereno hace como mucho 5 consultas por segundo a InternetDB. Si una IP
de un fichero falla (por ejemplo, porque Shodan limita el ritmo), el scan
se para y dice cuál fue.

Para reproducir esta receta (la única que sale a internet):

```bash
examples/run-examples.sh osint
```

## 17. Lo que esta página no cubre

| Qué | Por qué no está aquí |
|---|---|
| `tui` | Es interactiva; ver MANUAL §7. |
| `db migrate`, `db status`, `db verify` | Necesitan Postgres (`DATABASE_URL`). |
| Inputs shodan, censys, fofa, zoomeye, onyphe, binaryedge | Necesitan claves reales de esos servicios (InternetDB no: sección 16). |
| `s7 probe` | No hay simulador de S7 en el repo. |
| Comandos del build offensive (`write`, `exploit`, `proxy listen`, `harvest`, `dial`) | Escriben en equipos o marcan números; ver MANUAL §17. |
| `diff`, `init`, `proxy`, `repl`, `token` | Planificados: salen con 75 sin hacer nada. |
| `gen-man` | Genera páginas de man para empaquetar; ver MANUAL §19. |
