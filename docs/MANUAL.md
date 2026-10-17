# ElSereno, manual para dummies

Manual end-to-end con cada comando, ejemplos reales, variables
de entorno y workflows operativos. Pensado para alguien que
abre por primera vez el binario y quiere saber **qué hace, en
qué orden, con qué argumentos**.

> Si sólo quieres instalar el binario y empezar: salta a
> [§2 Instalación para dummies](#2-instalación-para-dummies).
> Si quieres desarrollar (clonar repo, compilar, levantar DB):
> ve a [`DEV-SETUP.md`](DEV-SETUP.md) y luego vuelve aquí.

---

## Índice

1. [¿Qué es ElSereno?](#1-qué-es-elsereno)
2. [Instalación para dummies](#2-instalación-para-dummies)
   1. [macOS](#21-macos)
   2. [Linux (Debian / Ubuntu / Fedora / Arch / Alpine)](#22-linux)
   3. [Docker / Kubernetes](#23-docker--kubernetes)
   4. [Verificación post-instalación](#24-verificación-post-instalación)
3. [Primer arranque (5 minutos)](#3-primer-arranque-5-minutos)
4. [Variables de entorno](#4-variables-de-entorno)
5. [Archivos y rutas](#5-archivos-y-rutas)
6. [Build variants](#6-build-variants-default--offensive--mini)
7. [CLI: referencia completa](#7-cli-referencia-completa)
   1. [scan, escanear targets](#71-scan)
   2. [discover, descubrir hosts vivos](#72-discover)
   3. [serve, dashboard + API](#73-serve)
   4. [vault, secretos cifrados](#74-vault)
   5. [creds, credenciales gestionadas](#75-creds)
   6. [db, operaciones de base de datos](#76-db)
   7. [audit, log de auditoría](#77-audit)
   8. [backup, copias cifradas](#78-backup)
   9. [config, configuración](#79-config)
   10. [plugins, plugins de protocolo](#710-plugins)
   11. [fingerprint, debug de plugins](#711-fingerprint)
   12. [triage, clasificar findings](#712-triage)
   13. [explain, explicar score](#713-explain)
   14. [scoring, ver pesos](#714-scoring)
   15. [doctor, preflight](#715-doctor)
   16. [tui, terminal UI](#716-tui)
   17. [api, meta de la HTTP API](#717-api)
   18. [legal · version · why · diff · proxy · repl · init · token](#718-otros-verbos)
8. [El dashboard web](#8-el-dashboard-web)
9. [Workflows típicos](#9-workflows-típicos)
10. [Troubleshooting](#10-troubleshooting)
11. [Glosario](#11-glosario)
12. [`scope.yaml`: limitar qué se puede tocar](#12-scopeyaml-reference)
13. [`elsereno.yaml`: configuración](#13-elserenoyaml-reference)
14. [Schema de finding (NDJSON v1)](#14-schema-de-finding-ndjson-v1)
15. [HTTP API reference (/api/v1/*)](#15-http-api-reference)
16. [Plugins por protocolo](#16-plugins-por-protocolo)
17. [Offensive build, triple-confirm + writes](#17-offensive-build)
18. [Deployment (systemd + Docker + K8s)](#18-deployment)
19. [Shell completion + man pages](#19-shell-completion--man-pages)
20. [Backup & disaster recovery](#20-backup--disaster-recovery)
21. [Performance tuning + capacity](#21-performance-tuning)
22. [FAQ rápida](#22-faq-rápida)

---

## 1. ¿Qué es ElSereno?

ElSereno es una herramienta CLI para **auditoría de exposición
de sistemas ICS/OT y redes legacy**. Recibe una lista de
hosts/puertos (o los descubre a partir de un CIDR), corre
"probes" específicos por protocolo (Modbus, OPC UA, BACnet,
S7, DNP3, CWMP, etc.) y emite **findings** (hallazgos)
puntuados con un score de severidad.

Dos modos de uso:

- **CLI por lotes**: `elsereno scan ...` produce NDJSON que
  se canaliza a `triage` / `explain` / SIEM externo.
- **Dashboard web**: `elsereno serve` levanta una UI en
  `http://127.0.0.1:8787` con scans interactivos, scheduling
  recurrente, audit log, merge-view para edición concurrente.

> **Importante (legal)**. ElSereno es para trabajos
> **autorizados**. No lo corras contra sistemas que no te
> pertenezcan o sobre los que no tengas permiso explícito.
> Ver `LEGAL.md` y `./elsereno legal`.

---

## 2. Instalación para dummies

Tres caminos posibles: paquete del sistema (recomendado para
operadores), tarball (laptops / kiosks), contenedor OCI (CI /
K8s). El binario **es estático sin dependencias**: no instala
nada en `/usr/lib`.

### 2.1 macOS

Apple Silicon (M1/M2/M3/M4) y Intel ambos soportados.

```bash
# Opción A, Homebrew tap (si está publicado):
brew install RobinR00T/tap/elsereno

# Opción B, Tarball manual:
ARCH=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')
curl -L "https://github.com/RobinR00T/elSereno/releases/latest/download/elsereno_darwin_${ARCH}.tar.gz" \
    | tar -xz -C /tmp
sudo mv /tmp/elsereno /usr/local/bin/
sudo chown root:wheel /usr/local/bin/elsereno
sudo chmod 0755 /usr/local/bin/elsereno
elsereno version
```

macOS quarantine: si Gatekeeper bloquea el binario:

```bash
xattr -d com.apple.quarantine /usr/local/bin/elsereno
```

### 2.2 Linux

#### Debian / Ubuntu

```bash
ARCH=$(dpkg --print-architecture)              # amd64 o arm64
VER=$(curl -s https://api.github.com/repos/RobinR00T/elSereno/releases/latest \
        | grep tag_name | cut -d '"' -f 4 | sed 's/^v//')
curl -L "https://github.com/RobinR00T/elSereno/releases/download/v${VER}/elsereno_${VER}_linux_${ARCH}.deb" \
    -o /tmp/elsereno.deb
sudo dpkg -i /tmp/elsereno.deb
elsereno version
```

#### Fedora / RHEL / Rocky / Alma

```bash
ARCH=$(uname -m)                               # x86_64 o aarch64
VER=$(curl -s https://api.github.com/repos/RobinR00T/elSereno/releases/latest \
        | grep tag_name | cut -d '"' -f 4 | sed 's/^v//')
sudo dnf install -y "https://github.com/RobinR00T/elSereno/releases/download/v${VER}/elsereno_${VER}_linux_${ARCH}.rpm"
elsereno version
```

#### Alpine

```bash
ARCH=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')
VER=$(wget -qO- https://api.github.com/repos/RobinR00T/elSereno/releases/latest \
        | grep tag_name | cut -d '"' -f 4 | sed 's/^v//')
wget -q "https://github.com/RobinR00T/elSereno/releases/download/v${VER}/elsereno_${VER}_linux_${ARCH}.apk" \
    -O /tmp/elsereno.apk
sudo apk add --allow-untrusted /tmp/elsereno.apk
elsereno version
```

#### Arch

```bash
yay -S elsereno      # si está en AUR
# o instala via .tar.gz manual:
ARCH=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')
VER=$(curl -s https://api.github.com/repos/RobinR00T/elSereno/releases/latest \
        | grep tag_name | cut -d '"' -f 4 | sed 's/^v//')
curl -L "https://github.com/RobinR00T/elSereno/releases/download/v${VER}/elsereno_${VER}_linux_${ARCH}.tar.gz" \
    | sudo tar -xz -C /usr/local/bin/
elsereno version
```

#### Tarball genérico (cualquier Linux)

```bash
ARCH=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')
VER=$(curl -s https://api.github.com/repos/RobinR00T/elSereno/releases/latest \
        | grep tag_name | cut -d '"' -f 4 | sed 's/^v//')
curl -L "https://github.com/RobinR00T/elSereno/releases/download/v${VER}/elsereno_${VER}_linux_${ARCH}.tar.gz" \
    | tar -xz -C /tmp
sudo install -m 0755 /tmp/elsereno /usr/local/bin/elsereno
elsereno version
```

### 2.3 Docker / Kubernetes

```bash
docker run --rm ghcr.io/robinr00t/elsereno:latest version

# Para serve con Postgres externo (compose mínimo):
docker run -d --name elsereno-serve \
    -p 127.0.0.1:8787:8787 \
    -e DATABASE_URL='postgres://user:pwd@db-host:5432/elsereno?sslmode=require' \
    -v ~/.elsereno:/root/.elsereno:ro \
    ghcr.io/robinr00t/elsereno:latest \
    serve --scan-store=db
```

> Las imágenes Docker oficiales se generan en CI cuando
> GitHub Actions está activo. Si CI está pausado, el
> tarball / paquete del sistema es la ruta canónica.

### 2.4 Verificación post-instalación

Cuatro comandos para confirmar que la instalación es correcta:

```bash
# 1) Binario alcanzable:
which elsereno                  # /usr/local/bin/elsereno (o similar)

# 2) Versión y commit:
elsereno version                # vX.Y.Z (commit ABC123, built YYYY-MM-DDTHH:MM:SSZ)

# 3) Disclaimer legal, debe mostrarse al menos una vez:
elsereno legal

# 4) Preflight: comprueba paths, perms, vault, db reachability:
elsereno doctor
```

Si `doctor` reporta problemas, los detalla con el path /
permiso esperado vs. el observado.

---

## 3. Primer arranque (5 minutos)

Del binario recién instalado a un dashboard funcionando.

```bash
# 1) Disclaimer legal (sólo la primera vez, lo marca en el log):
elsereno legal

# 2) Crear el vault cifrado donde se guardan credenciales y la
#    master key para CSRF / backup encryption:
elsereno vault init
#    Te pedirá una passphrase. ÚSALA FUERTE. Si la olvidas,
#    perderás acceso al vault, no hay recuperación.

# 3) Desbloquear el vault (necesario antes de cada serve):
elsereno vault unlock

# 4) (Opcional, recomendado) Inicializar config canónico:
elsereno config show > ~/.elsereno/elsereno.yaml
# Edita el archivo a tu gusto; las claves están documentadas en
# .context/conventions.md.

# 5) (Opcional) Para persistencia entre reinicios, apunta a
#    una Postgres y migra:
export DATABASE_URL='postgres://elsereno:****@db-host:5432/elsereno?sslmode=require'
elsereno db migrate up

# 6) Levantar el dashboard:
elsereno serve --scan-store=db    # con DB persistente
# o
elsereno serve --scan-store=memory # sin DB (datos volátiles)
```

Dashboard en `http://127.0.0.1:8787`. Login no se requiere por
defecto (loopback bind); si lo expones fuera de loopback,
serve **exige** TLS + `--i-know-what-im-doing`.

---

## 4. Variables de entorno

| Variable                          | Por defecto                              | Uso                                                    |
|-----------------------------------|------------------------------------------|--------------------------------------------------------|
| `DATABASE_URL`                    | (vacío → 503)                            | URL Postgres para `--scan-store=db` y `db migrate`.    |
| `ELSERENO_CONFIG`                 | `~/.elsereno/elsereno.yaml`              | Path al config; lo sobreescribe `--config`.            |
| `ELSERENO_WEB_BIND`               | `127.0.0.1:8787`                         | Bind por defecto de `serve`.                           |
| `ELSERENO_WEB_TOKEN_TTL_DAYS`     | `30`                                     | TTL de tokens web.                                     |
| `ELSERENO_LOG_LEVEL`              | `info`                                   | `debug` / `info` / `warn` / `error`.                   |
| `ELSERENO_VAULT_PASSPHRASE`       | (vacío)                                  | **No usar en prod**: pasa el passphrase al vault via env. Equivalente a `--vault-passphrase-file` pero más inseguro (PITF-032). |
| `OTEL_EXPORTER_OTLP_ENDPOINT`     | (vacío)                                  | Endpoint OpenTelemetry para traces / metrics.          |
| `SHODAN_API_KEY`                  | (vacío)                                  | Clave API Shodan; prefiere `elsereno creds store`.     |
| `CENSYS_API_ID` / `CENSYS_API_SECRET` | (vacío)                              | Credenciales Censys; prefiere creds.                   |
| `FOFA_EMAIL` / `FOFA_KEY`         | (vacío)                                  | Credenciales FOFA; prefiere creds.                     |
| `ZOOMEYE_API_KEY`                 | (vacío)                                  | ZoomEye; prefiere creds.                               |
| `ONYPHE_API_KEY`                  | (vacío)                                  | ONYPHE; prefiere creds.                                |
| `PGPASSFILE`                      | (vacío)                                  | Path al `.pgpass` (mode 0600); alternativa al env.     |
| `PGSERVICEFILE`                   | (vacío)                                  | Path al `pg_service.conf`.                             |

**Regla de oro** (PITF-032): secretos persistentes van en
archivos `0600`, **no** en env vars o argv. `ELSERENO_VAULT_PASSPHRASE`
sólo está admitido para CI / cron con rationale documentado.

---

## 5. Archivos y rutas

```
~/.elsereno/
├── elsereno.yaml       # config (opcional, ELSERENO_CONFIG lo sobreescribe)
├── vault.v1.bin        # vault encriptado (AES-256-GCM, key from passphrase)
├── audit.jsonl         # audit log file-backed (chain con HMAC)
├── dev.pp              # (sólo dev) passphrase del vault, 0600
├── dev-db.env          # (sólo dev) DATABASE_URL para dev-db.sh
└── gh-token            # (legacy, borrable) bootstrap PAT, ver hygiene
```

- `vault.v1.bin`: cifrado con la passphrase. Pérdida =
  pérdida total de credenciales gestionadas.
- `audit.jsonl`: append-only con hash chain (no editar a
  mano).
- `dev.pp`: sólo en máquina de desarrollo, mode 0600. Nunca
  copiar a producción.

---

## 6. Build variants (default / offensive / mini)

| Variant       | Binary name           | Incluye                                                 | Excluye                          | Tamaño   |
|---------------|-----------------------|---------------------------------------------------------|----------------------------------|----------|
| **default**   | `elsereno`            | scan, discover, dashboard, TUI, 35 plugins read-only    | writes / dial / harvest          | ~23.2 MB |
| **offensive** | `elsereno-offensive`  | todo lo anterior + 18 proxies write-gated + dial + SMS  | nada                             | ~23.9 MB |
| **mini**      | `elsereno-mini`       | todo default menos `serve` / `api` / `tui`              | dashboard + OpenAPI + TUI        | ~21.5 MB |

- **default** es lo que necesitas el 90 % del tiempo.
- **offensive** sólo si vas a hacer pen-test autorizado con
  escrituras a ICS. Triple-confirm fences obligatorios.
- **mini** para hosts embedded / jump-hosts donde el
  dashboard sobra y quieres menos superficie.

Default + offensive pueden coexistir en el mismo host
(binarios distintos). Mini es excluyente.

---

## 7. CLI: referencia completa

Convenciones para los ejemplos:

- `TARGET_FILE` = archivo de texto con un host:port por línea.
- `OUTPUT.ndjson` = donde dejas el output NDJSON.
- Flags globales: `--config`, `--dry-run`, `--format`, `--verbose`,
  `--quiet`. Ojo: `--dry-run` solo lo implementan `schedule delete`,
  `enable`, `disable`, `clone`, `import`, `pause-all` y `resume-all`; los
  demás se niegan a arrancar con él (salida 64, "nothing was run"). Hasta
  el 16-10-2026 lo ignoraban y actuaban de verdad (`scan` escaneaba).

### 7.1 `scan`

Escanea targets aplicando los plugins de protocolo
correspondientes a cada puerto: cada plugin sondea los targets cuyo
puerto es su puerto por defecto (`dnp3` el 20000, `modbus` el 502…),
y `banner`, que no tiene puerto, sondea todos. Los plugins opt-in
(`s7-exposure`, `opcua-exposure`, `codesys-active`) solo corren si se
nombran en `--plugin`, y como no tienen puerto por defecto van, igual
que `banner`, contra TODOS los targets de la lista, sea cual sea su
puerto (`scan` lo avisa por stderr): lista solo los hosts de su
protocolo, o usa `fingerprint probe`. Es el mismo reparto que usan los
scans del dashboard. Cada finding sale con la dirección y el puerto del target.
Para sondear un plugin en un puerto que no es el suyo, `fingerprint
probe` (§ más abajo).

Hasta el 7-10-2026 la CLI solo lanzaba `banner`, aunque esta sección
ya prometía el reparto por protocolo, y la salida dejaba `address`
vacío y `port` a 0.

**Flags importantes:**

| Flag                       | Por defecto    | Uso                                                                   |
|----------------------------|----------------|-----------------------------------------------------------------------|
| `--input KIND`             | (requerido)    | `list:FILE`, `nmap:FILE`, `stdin`, `shodan:Q`, `censys:Q`, `fofa:Q`, `zoomeye:Q`, `onyphe:Q`, `internetdb:IP_o_CIDR` |
| `--plugin NAME[,NAME]`     | (todos)        | solo esos plugins (repetible); cada uno limitado a su puerto, salvo los opt-in sin puerto (abajo) |
| `--output-format`          | `ndjson`       | `ndjson`, `csv` o `stix`                                              |
| `--output FILE`            | `-` (stdout)   | path al fichero de salida                                             |
| `--default-port N`         | (sin)          | si las líneas no traen `:port`, se aplica este                        |
| `--max-concurrent N`       | (config)       | targets paralelos                                                     |
| `--api-creds-file YAML`    | (sin)          | 0600 YAML con creds shodan/censys/fofa/zoomeye/onyphe                 |
| `--scope FILE.yaml`        | (sin)          | scope.yaml; descarta los targets fuera de sus rangos o puertos, y no lanza los plugins fuera de `protocols` (§12) |
| `--no-progress`            | `false`        | desactiva barra de progreso (CI-friendly)                             |

**Ejemplos:**

```bash
# Escanear un archivo de targets, NDJSON a stdout:
elsereno scan --input list:targets.txt > findings.ndjson

# Sólo IPs sin puerto + plugin "modbus" forzando puerto 502:
echo "10.0.0.1" > targets.txt
elsereno scan --input list:targets.txt --default-port 502 > findings.ndjson

# Pipe nmap → elsereno:
nmap -sV 10.0.0.0/24 -oX nmap.xml
elsereno scan --input nmap:nmap.xml > findings.ndjson

# Usar Shodan como fuente de targets (necesita api-creds-file):
cat > /tmp/api-creds.yaml <<EOF
shodan:
  key: "${SHODAN_API_KEY}"
EOF
chmod 0600 /tmp/api-creds.yaml
elsereno scan --input shodan:'port:502 country:ES' --api-creds-file /tmp/api-creds.yaml \
    > findings.ndjson

# CSV en lugar de NDJSON:
elsereno scan --input list:targets.txt --output-format csv --output findings.csv

# Solo DNP3 y Modbus (cada uno en su puerto):
elsereno scan --input list:targets.txt --plugin dnp3,modbus

# Stdin (encadenable):
echo -e "10.0.0.1:502\n10.0.0.2:44818" | elsereno scan --input stdin > findings.ndjson
```

### 7.2 `discover`

Sweep de un CIDR (o lista de hosts) para detectar puertos
de cualquier plugin registrado. Es un **TCP-connect sweep**,
no fingerprint, el output suele encadenarse a `scan`.

**Flags importantes:**

| Flag           | Por defecto | Uso                                                       |
|----------------|-------------|-----------------------------------------------------------|
| `--auto CIDR`  | (sin)       | sweep automático sobre el CIDR                            |
| `--hosts FILE` | (sin)       | sweep contra una lista de IPs (un IP por línea, `#` comments) |

`--auto` y `--hosts` son mutuamente exclusivos.

**Ejemplos:**

```bash
# Discover una /24 y luego scan sobre lo vivo:
elsereno discover --auto 10.0.0.0/24 --format list \
    | elsereno scan --input list:- > findings.ndjson

# Discover sobre lista curada de hosts:
cat > hosts.txt <<EOF
10.0.0.1
10.0.0.2
# 10.0.0.3, host fuera de mantenimiento
10.0.0.5
EOF
elsereno discover --hosts hosts.txt > responsive.ndjson
```

### 7.3 `serve`

Levanta el dashboard HTTP + `/api/v1`. Necesita un vault
inicializado y desbloqueado (CSRF key se deriva del master).

**Flags importantes:**

| Flag                          | Por defecto       | Uso                                                                   |
|-------------------------------|-------------------|-----------------------------------------------------------------------|
| `--addr HOST:PORT`            | `127.0.0.1:8787`  | bind. Loopback default; non-loopback exige TLS + `--i-know-what-im-doing`. |
| `--tls-cert FILE`             | (sin)             | certificado PEM para non-loopback                                     |
| `--tls-key FILE`              | (sin)             | clave privada PEM                                                     |
| `--i-know-what-im-doing`      | `false`           | confirmación obligatoria para non-loopback                           |
| `--vault-passphrase-file FILE`| (sin → interactivo) | path a passphrase 0600 (ADR-026, PITF-016)                          |
| `--scan-store off\|memory\|db` | `off`             | backend del scan-orch. `off` → /api/v1/scans devuelve 503.            |
| `--scan-pool N`               | `2`               | concurrencia del worker pool, clamped [1,64]                         |
| `--audit-retention-days N`    | `0` (off)         | v1.87+: spawnea pruner diario que borra audit events > N días        |

**Ejemplos:**

```bash
# Dev rápido (loopback, memory store, vault interactivo):
elsereno vault unlock
elsereno serve --scan-store=memory

# Dev con persistencia (loopback + Postgres):
export DATABASE_URL='postgres://elsereno@127.0.0.1:5433/elsereno?sslmode=disable'
elsereno serve --scan-store=db --vault-passphrase-file ~/.elsereno/dev.pp

# Producción (TLS + non-loopback + retención 90d):
elsereno serve \
    --addr 10.0.0.5:8787 \
    --tls-cert /etc/elsereno/server.crt \
    --tls-key /etc/elsereno/server.key \
    --i-know-what-im-doing \
    --scan-store=db \
    --scan-pool 8 \
    --audit-retention-days 90 \
    --vault-passphrase-file /etc/elsereno/vault.pp
```

Salida: una vez arrancado verás `elsereno serve: listening on 127.0.0.1:8787`.

**Qué hace con los scans.** Desde el 17-10-2026 los jobs que se encolan
desde el dashboard, la API o un schedule se ejecutan en el pool de
workers (`--scan-pool`): **mandan tráfico real a sus targets**, con el
mismo reparto por puerto que `scan` (§7.1). Antes se quedaban en
`queued` para siempre (PITF-094). Con `--scope`, los targets fuera de
scope se descartan antes de sondear y los plugins fuera de `protocols`
no corren (§12); sin él no hay límite.

- Los findings van siempre al stream SSE (`/api/v1/stream`: `run_start`,
  `finding`, `run_end`) y, si hay `DATABASE_URL`, a las tablas `runs`,
  `targets` y `findings` que leen el dashboard y
  `/api/v1/{runs,findings}` (necesitan `elsereno db migrate up`). Si un
  finding no se puede guardar, el job falla en vez de dar por buenos
  resultados que nadie podrá leer.
- Los jobs que ya estaban en cola al arrancar `serve` no se ejecutan: es
  el atasco de cuando nada los ejecutaba, o lo que dejó un `serve`
  parado. `serve` avisa una vez de cuántos son; cancélalos
  (`POST /api/v1/scans/{id}/cancel`) o vuelve a lanzarlos.
- Al arrancar, `serve` dice cuántos schedules activos hay. Cada uno lanza
  un scan real cuando le toca, y el primer tick dispara todos los que ya
  tocaban: revísalos (`GET /api/v1/schedules`) antes de actualizar.
- El detalle de un job (`GET /api/v1/scans/{id}`) da contadores, no sus
  findings, y el job todavía no apunta a su run: los findings están en
  `/api/v1/findings`, y el run en `/api/v1/runs`, con la hora de inicio
  del job (TODO-vNext).
- Un job en curso se cancela con `POST /api/v1/scans/{id}/cancel` o el
  botón Cancel: en un segundo como mucho deja de abrir conexiones, la
  sonda que ya estaba en marcha acaba sola (hasta su timeout) y su
  finding se guarda, y el run queda `cancelled`. Un cancel que llega
  justo cuando el scan termina deja el job `cancelled` y el run
  `completed`. Hasta el 17-10-2026 el cancel solo cambiaba el
  estado y el scan seguía.
- Respeta los límites de la config, `scanner.max_concurrent_targets` y
  `scanner.max_concurrent_per_host` (§13), como `scan`.
- Clonar un schedule conserva su estado: el clon de uno desactivado nace
  desactivado (hasta el 17-10-2026 todo clon nacía activo).
- Si `serve` se para con un job en `running`, el job se queda así: nada
  lo recupera al arrancar (TODO-vNext). Un solo `serve` por base de
  datos: con dos, el Scheduler puede disparar dos veces el mismo
  schedule.

Ctrl+C envía SIGINT → exit 130; SIGTERM → exit 143.

### 7.4 `vault`

Gestión del vault cifrado.

**Sub-comandos:**

| Sub-comando  | Qué hace                                                              |
|--------------|-----------------------------------------------------------------------|
| `init`       | Crea el vault. Pide passphrase. **Falla** si ya existe (no se sobreescribe, PITF-021). |
| `unlock`     | Desbloquea el vault en la memguard del proceso CLI. Útil para precargar antes de `serve`. |
| `lock`       | Zeroiza la copia en memoria. Útil tras usar `creds show --reveal`.    |
| `status`     | Reporta si existe + dónde vive.                                       |

**Flags importantes (en `init` / `unlock`):**

| Flag                              | Uso                                                       |
|-----------------------------------|-----------------------------------------------------------|
| `--vault-passphrase-file FILE`    | passphrase desde fichero 0600 (no interactivo)            |

**Ejemplos:**

```bash
# Primera vez:
elsereno vault init
# Te pide passphrase 2 veces. Crea ~/.elsereno/vault.v1.bin.

# Equivalente no interactivo (dev / CI):
umask 077
openssl rand -base64 16 > ~/.elsereno/dev.pp
elsereno vault init --vault-passphrase-file ~/.elsereno/dev.pp

# Verificar:
elsereno vault status     # → "vault: initialised (/path/to/vault.v1.bin)"

# Olvidaste la passphrase? Sólo opción: borrar el vault + re-init
# (perderás credenciales gestionadas):
rm ~/.elsereno/vault.v1.bin
elsereno vault init
```

### 7.5 `creds`

Credenciales (api keys, etc.) gestionadas dentro del vault.
Sustituye a las env vars de `SHODAN_API_KEY` etc.

| Sub-comando | Uso                                                              |
|-------------|------------------------------------------------------------------|
| `store`     | Guarda una credencial nueva. Lee plaintext de stdin (no argv, PITF-032). |
| `rotate`    | Sobrescribe una existente.                                       |
| `show`      | Imprime metadata (nombre, fecha). Con `--reveal` imprime también el plaintext + escribe entrada en audit. |
| `list`      | Lista nombres de creds guardadas.                                |
| `purge`     | Borra una cred.                                                  |

**Ejemplos:**

```bash
# Guardar la api key de Shodan (pide passphrase y valor sin eco):
elsereno creds store shodan_api_key
# Por tubería, creds store y rotate leen DOS líneas de stdin: la
# passphrase del vault y después el valor (sin TTY no preguntan).

# Listar lo guardado:
elsereno creds list

# Ver plaintext (todavía no queda en la cadena de auditoría; solo
# avisa por stderr):
elsereno creds show shodan_api_key --reveal

# Rotar (reemplazar; pide passphrase y valor nuevo):
elsereno creds rotate shodan_api_key

# Borrar:
elsereno creds purge shodan_api_key
```

### 7.6 `db`

Operaciones contra Postgres (sólo aplicable si usas
`--scan-store=db`).

| Sub-comando        | Uso                                                  |
|--------------------|------------------------------------------------------|
| `migrate up`       | Aplica todas las migraciones pendientes.             |
| `migrate down`     | Revierte la última migración (úsalo con cuidado).    |
| `status`           | Reporta `applied vs pending`.                        |
| `verify`           | Confirma que el schema es alcanzable y conocido.     |

**Ejemplos:**

```bash
# Exportar la URL:
export DATABASE_URL='postgres://elsereno:****@host:5432/elsereno?sslmode=require'

# Ver pendientes:
elsereno db status

# Aplicar todo:
elsereno db migrate up

# Rollback de la última (cuidado):
elsereno db migrate down

# Validar:
elsereno db verify
```

### 7.7 `audit`

El audit log es **append-only con hash-chain HMAC**.
Garantiza tamper-evidence; cualquier edición externa rompe
la chain y `verify` lo detecta.

| Sub-comando     | Uso                                                                   |
|-----------------|-----------------------------------------------------------------------|
| `verify`        | Verifica la chain (tail o full). Exit-0 si íntegro.                   |
| `verify-file`   | Idem pero contra el chain file-backed (`~/.elsereno/audit.jsonl`).    |
| `compact`       | Borra entradas anteriores a cutoff; inserta `chain_rebase` marker.   |
| `purge`         | Tombstone-purge antes de cutoff (preserva chain).                     |
| `serve`         | Daemon UDS centralizado (v1.26+, para múltiples processes).           |

`audit verify`, `audit compact` y `audit purge` están declarados pero
no hacen nada todavía: tras validar sus flags salen con 69 (el escritor
de la cadena en la base de datos está pendiente). La verificación que
funciona hoy es la del fichero, `audit verify-file`.

**Ejemplos:**

```bash
# Verificar full chain del archivo:
elsereno audit verify-file


# Levantar daemon UDS:
elsereno audit serve --socket /var/run/elsereno-audit.sock
```

### 7.8 `backup`

Backups cifrados AES-256-GCM con clave derivada del vault.
**Requiere vault desbloqueado** (la master key cifra el
backup envelope).

| Sub-comando | Uso                                                            |
|-------------|----------------------------------------------------------------|
| `create`    | Crea un fichero cifrado con `vault.v1.bin` (solo eso).         |
| `inspect`   | Describe el envelope SIN descifrar: magic, versión, sal, nonce, tamaño y modo. |
| `restore`   | Descifra a un directorio que ya existe; solo donde el vault original existe. |

Ojo: la clave del backup se deriva del propio vault, así que no sirve
para recuperarse de perderlo (§20, PITF-093).

**Ejemplos:**

```bash
# Crear backup (pide la passphrase):
elsereno backup create --out /backups/elsereno-2026-05-11.tar.gz.enc

# Inspeccionar sin descifrar:
elsereno backup inspect --in /backups/elsereno-2026-05-11.tar.gz.enc

# Restaurar (requiere mismo vault master; --to tiene que existir):
install -d -m 0700 /tmp/restored
elsereno backup restore --in /backups/elsereno-2026-05-11.tar.gz.enc --to /tmp/restored
```

### 7.9 `config`

| Sub-comando | Uso                                              |
|-------------|--------------------------------------------------|
| `show`      | Imprime la config efectiva (defaults + overrides). |
| `lint`      | Valida `elsereno.yaml` + scope opcional.         |

**Ejemplos:**

```bash
# Ver config efectiva:
elsereno config show

# Volcar a archivo + editar:
elsereno config show > ~/.elsereno/elsereno.yaml
$EDITOR ~/.elsereno/elsereno.yaml

# Validar:
elsereno config lint
# o con flag global:
elsereno --config /path/to/other.yaml config lint
```

### 7.10 `plugins`

Inspeccionar los plugins de protocolo compilados en este
binario.

| Sub-comando | Uso                                                                    |
|-------------|------------------------------------------------------------------------|
| `list`      | Lista todos los plugins (nombre, puertos default, write-gated?).        |
| `ports`     | Mapa inverso: puerto → plugins. Útil para "qué probe va al 502?".      |

**Ejemplos:**

```bash
# Todos los plugins:
elsereno plugins list

# Map de puertos:
elsereno plugins ports

# Filtrar (tu mismo, no es flag nativo):
elsereno plugins list | grep modbus
```

### 7.11 `fingerprint`

Debug de plugins: capturar bytes reales + validar contra
ellos.

| Sub-comando | Uso                                                                |
|-------------|--------------------------------------------------------------------|
| `capture`   | Escucha en `--listen` y guarda los bytes del cliente en `--output`. |
| `validate`  | Corre `Probe()` de un plugin contra bytes capturados (offline); muestra match score. |
| `probe`     | Fingerprint EN VIVO de un solo target con un plugin: abre una conexión real a `--target host:port` y muestra el Finding. |

**Ejemplos:**

```bash
# Capturar bytes que un cliente envía al puerto 502:
elsereno fingerprint capture --listen 127.0.0.1:5020 --output /tmp/modbus.bin
# (en otra terminal: nmap o cliente real → 127.0.0.1:5020)

# Validar (offline) contra un plugin:
elsereno fingerprint validate --plugin modbus --file /tmp/modbus.bin
# Salida: capability score + reasoning

# Probe en vivo de un solo target con un plugin concreto:
elsereno fingerprint probe --plugin opcuahttps --target 10.0.0.5:4843 --json
# (contrasta con `scan`, que reparte cada target entre los plugins de su
# puerto, y con `validate`, offline)
```

### 7.12 `triage`

Agrupa findings en buckets: quick-win / strategic / utility /
routine. Útil para priorizar.

**Flag importante:**

| Flag             | Uso                                            |
|------------------|------------------------------------------------|
| `--from-file F`  | leer findings desde F (default: stdin)         |

**Ejemplos:**

```bash
# Pipe completo:
elsereno scan --input list:targets.txt | elsereno triage

# Desde archivo:
elsereno triage --from-file findings.ndjson
```

Salida agrupada: una sección por bucket con los findings
de ese bucket.

### 7.13 `explain`

Toma UN finding (NDJSON v1 shape) y explica cómo se computó
su score: factor por factor.

```bash
# Ver explicación del primer finding:
head -1 findings.ndjson | elsereno explain

# Desde fichero:
elsereno explain --from-file single-finding.ndjson
```

Salida: tabla con `factor`, `weight`, `contribution`, +
severidad derivada.

### 7.14 `scoring`

Imprime los pesos + umbrales (ADR-006) usados por el
scorer.

```bash
elsereno scoring
# Salida: tabla con factors y sus weights.
```

### 7.15 `doctor`

Preflight cross-platform: paths, perms, vault, DB
reachability, build variant, etc.

```bash
elsereno doctor
# Exit-0 si todo OK. Si algo falla, dice exactamente qué.
```

Buen primer comando tras instalar o tras tocar la config.

### 7.16 `tui`

Terminal UI interactivo (bubbletea). Sólo disponible en
default + offensive (no en mini).

**Flags importantes:**

| Flag                  | Uso                                                                 |
|-----------------------|---------------------------------------------------------------------|
| (sin)                 | modo interactivo con paneles vacíos (sanity check)                  |
| `--input KIND`        | scan desde el TUI; misma sintaxis que `scan` (`list:F`, `stdin`, etc.) |
| `--replay FILE`       | revisa un NDJSON pre-grabado                                        |
| `--feed -`            | consume NDJSON desde stdin                                          |
| `--watch URL --bearer T` | suscribirse a SSE stream remoto                                   |
| `--record FILE.ndjson`| (v1.41+) graba el feed para replay                                  |
| `--rate FLOAT`        | (v1.43+) velocidad de replay (1.0 = tiempo real, 2.0 = 2× rápido)   |
| `--api-creds-file F`  | para inputs API-keyed                                               |

**Ejemplos:**

```bash
# UI vacío (test):
elsereno tui

# Scan vivo con el TUI:
elsereno tui --input list:targets.txt

# Replay de una sesión grabada:
elsereno tui --replay findings.ndjson --rate 2.0

# Consumir SSE remoto:
elsereno tui --watch https://remote-serve:8787/api/v1/stream --bearer "$TOKEN"
```

### 7.17 `api`

Meta-operaciones sobre la HTTP API.

```bash
# Imprimir el OpenAPI 3.1 spec generado del código:
elsereno api openapi > openapi.yaml
```

### 7.18 Otros verbos

| Verbo     | Estado    | Para qué sirve                                                    |
|-----------|-----------|-------------------------------------------------------------------|
| `legal`   | listo     | Imprime el disclaimer de uso autorizado.                          |
| `version` | listo     | Imprime version, commit hash, build date.                         |
| `why`     | listo     | Explica la postura de scoring para un target (planeado expansivo). |
| `diff`    | planned   | Comparar dos runs.                                                |
| `proxy`   | planned   | Proxy de interception protocol-aware.                            |
| `repl`    | planned   | REPL de protocolo interactivo.                                   |
| `init`    | planned   | Wizard de primera ejecución.                                     |
| `token`   | planned   | Operaciones de web token (rotate / show).                        |
| `gen-man` | planned   | Generar man pages desde cobra; hoy las genera `scripts/gen-manpages.sh`. |
| `fmt`     | listo     | Re-emite YAML con formato canónico.                               |
| `lint`    | listo     | Valida `elsereno.yaml` + `scope.yaml`.                            |
| `help`    | listo     | Ayuda sobre cualquier comando.                                    |
| `completion` | planned | Shell completions (bash/zsh/fish); hoy sale con 75.               |

### 7.1 Probes de exposición profunda (read-only) y trazabilidad

Más allá del fingerprint, estos comandos confirman la exposición en el
hilo. Todo es read-only salvo `creds-check`, que vive en el build
offensive y exige `--confirm-authorized` (uso autorizado).

```sh
# S7: nivel de protección + identidad/firmware en un handshake
elsereno s7 probe            --target plc:102 --json
elsereno s7 probe-protection --target plc:102
elsereno s7 probe-identity   --target plc:102
# OPC UA: ¿abre sesión anónima? ¿qué puede escribir el anónimo?
elsereno opcua probe-anon  --target plc:4840 --json
elsereno opcua probe-write --target plc:4840 --max-nodes 500
# Transporte en claro: ¿el servicio negocia TLS? Si lo negocia, también
# reporta postura TLS (acepta TLS 1.0/1.1 obsoletos, cert caducado).
elsereno plaintext-check --target plc:502 --json
elsereno plaintext-check --target hmi:443 --json   # postura TLS
# Findings puntuados opt-in (OptIn: NO en el scan por defecto; DefaultPort 0: NO en
# discover. Nombrados en scan --plugin van contra todos los targets de la lista):
elsereno fingerprint probe --plugin s7-exposure    --target plc:102  --json
elsereno fingerprint probe --plugin opcua-exposure --target plc:4840 --json
# Credenciales por defecto (build offensive, USO AUTORIZADO):
elsereno-offensive creds-check http --target https://hmi.internal --confirm-authorized
# Catálogo de trazabilidad al estándar:
elsereno standards --protocol opcua-exposure --json
```

Cada finding lleva la vulnerabilidad del NIST SP 800-82 r4 que evidencia,
en todas las salidas (ndjson, informe HTML, GitHub/Jira, CEF, syslog,
STIX, webhook). Guía completa: [`exposure-auditing.md`](exposure-auditing.md);
estado de validación de cada parser contra captura real:
[`parser-validation.md`](parser-validation.md).

---

## 8. El dashboard web

Tras `elsereno serve`, abre `http://127.0.0.1:8787`. Verás:

### Paneles principales

- **Scans**: jobs recientes con su estado (queued/running/
  completed/failed/cancelled) y un botón Cancel para los que
  están en cola o en curso (§7.3). Sus findings están en el
  panel Findings y en el live feed, que dice dirección y puerto.
- **Submit a scan**: textarea para pegar targets o cargar
  archivo. Selecciona plugins + dispara. Es un scan real contra esos
  targets (§7.3).
- **Schedules** (v1.70+): scans recurrentes con cron o
  interval. CRUD inline. Botón "History" abre el audit log
  por schedule.
- **Findings**: paginación con filtros (severity, plugin,
  target).
- **Triage**: counts por bucket (v1.2+).
- **Reload cadence**: gráfica de SIGUSR1 reloads (v1.19+).
- **Runs**: histórico de runs con timing.
- **Audit**: chain status + last entries.

### Acciones contextuales

- **Per-schedule**: Edit · Enable/Disable · History · Delete.
- **Edit form**: con preview de "next fire" (cron debounced
  350ms, multi-fire si es cron mode v1.79+).
- **Concurrent edit detection** (v1.78+): si otro operador
  cambió el schedule mientras tú editas, 412 → merge-view
  panel con diff por campo + radio "mine/server" (v1.83+).
- **Force overwrite** (v1.81+): re-submit sin If-Match;
  graba audit event `force_overwrite`.

### Autenticación

Loopback default no exige login. Para non-loopback bind, el
serve emite tokens TTL=30d (configurable). Login en
`/admin/security` por ahora rudimentario; OIDC vNext.

---

## 9. Workflows típicos

### 9.1 Scan ad-hoc + triage

```bash
echo -e "10.0.0.1\n10.0.0.2:502" > targets.txt
elsereno scan --input list:targets.txt --default-port 502 \
    | tee findings.ndjson \
    | elsereno triage
```

### 9.2 Discover → scan automático sobre una /24

```bash
elsereno discover --auto 10.0.0.0/24 --format list \
    | elsereno scan --input list:- \
    > findings.ndjson
```

### 9.3 Pipeline completo a CSV para reporting

```bash
elsereno scan --input list:targets.txt --output-format csv > findings.csv
# Después abres en Excel/Sheets.
```

### 9.4 Scan periódico via cron del sistema

```bash
# crontab -e
0 */6 * * * /usr/local/bin/elsereno scan \
    --input list:/etc/elsereno/targets.txt \
    --output /var/lib/elsereno/findings-$(date +\%Y\%m\%dT\%H).ndjson \
    --no-progress
```

### 9.5 Scan recurrente vía dashboard (en lugar de cron)

Dashboard → Schedules → Create:
- Name: `fleet-modbus-6h`
- Input: `list:/etc/elsereno/targets.txt`
- Plugins: `modbus`
- Cadence: cron `0 */6 * * *`
- Timezone: `America/New_York`

El Scheduler en serve dispara cada 6h, y cada disparo es un scan real
(hasta el 17-10-2026 el job se quedaba en cola, PITF-094). Audit log
registra cada fire. v1.78+ optimistic locking previene races si otro
operador edita.

### 9.6 Investigar un finding sospechoso

```bash
# Encontrar el finding:
grep "10.0.0.5" findings.ndjson > suspect.ndjson

# Ver score:
elsereno explain --from-file suspect.ndjson

# Ver score detallado de ese tipo:
elsereno scoring
elsereno why 10.0.0.5:502
```

### 9.7 Backup periódico

`backup create` no sirve si pierdes el vault (§20). Copia los ficheros
tal cual; `vault.v1.bin` ya va cifrado con la passphrase:

```bash
#!/usr/bin/env bash
# Diario; borra las copias de más de 7 días.
set -euo pipefail
D=/backups/elsereno/$(date +%Y%m%d)
DEST=$D
install -d -m 0700 "$D"
install -m 0600 ~/.elsereno/vault.v1.bin "$D/"
# La config, de donde la lee elSereno (orden de §13):
for c in "${ELSERENO_CONFIG:-}" "${XDG_CONFIG_HOME:-$HOME/.config}/elsereno/elsereno.yaml" \
         "$HOME/.config/elsereno/elsereno.yaml" "$HOME/.elsereno/elsereno.yaml"; do
  if [ -n "$c" ] && [ -e "$c" ]; then install -m 0600 "$c" "$DEST/elsereno.yaml"; break; fi
done
# audit.jsonl no existe hasta que algo escribe en él (los verbos del
# build offensive o `audit serve`):
if [ -e ~/.elsereno/audit.jsonl ]; then install -m 0600 ~/.elsereno/audit.jsonl "$D/"; fi
find /backups/elsereno -mindepth 1 -maxdepth 1 -mtime +7 -exec rm -rf {} +
```

### 9.8 Rotar credenciales API

```bash
# Genera nueva key en Shodan → la rotas (pide passphrase y valor):
elsereno creds rotate shodan_api_key
# Verifica:
elsereno creds list
elsereno scan --input shodan:'port:502' ...   # debe usar la nueva
```

### 9.9 Tras restart del servidor: bring-up del dashboard

```bash
# (Si usas el dev tooling, ver DEV-SETUP.md):
scripts/start.sh

# Manual:
docker compose -f docker-compose.dev.yml up -d db
export DATABASE_URL='postgres://elsereno@127.0.0.1:5433/elsereno?sslmode=disable'
elsereno serve --scan-store=db --vault-passphrase-file ~/.elsereno/dev.pp
```

### 9.10 Pruning manual del audit (sin pruner automático)

```bash
# Borra audit events de schedules > 90 días:
cutoff=$(date -u -v-90d '+%Y-%m-%dT%H:%M:%SZ')   # macOS
curl -X DELETE "http://127.0.0.1:8787/api/v1/schedules/audit?before=$cutoff"
```

Con pruner automático:

```bash
elsereno serve --scan-store=db --audit-retention-days 90 \
    --vault-passphrase-file ~/.elsereno/dev.pp
```

---

## 10. Troubleshooting

| Síntoma                                                          | Causa probable                                         | Solución                                                                  |
|------------------------------------------------------------------|--------------------------------------------------------|---------------------------------------------------------------------------|
| `vault: not initialised`                                         | Primera ejecución sin `vault init`                     | `elsereno vault init`                                                     |
| `serve: bind 0.0.0.0:8787 requires --tls-cert/--tls-key`         | Non-loopback bind sin TLS                              | Añade certs + `--i-know-what-im-doing`                                    |
| `failed to authenticate caller: error obtaining token: expired_token` (cosign) | Device flow OIDC expira en 300s              | Re-ejecuta + abre el URL inmediatamente, o `--skip=sign`                  |
| `migrations failed, see output above`                           | Binario stale (no conoce las últimas migraciones)      | Rebuild: `go build -o elsereno ./cmd/elsereno && elsereno db migrate up`  |
| `Did not find any relation named "scan_schedule_audit"`          | Idem (migration 00011/00012 no aplicada por binario stale) | Mismo fix de arriba                                                       |
| `HTTP 401: Bad credentials` al usar `gh`                         | PAT revocado o expirado                               | `gh auth login -h github.com`                                             |
| `error=missing GITHUB_TOKEN, GITLAB_TOKEN and GITEA_TOKEN` (goreleaser) | Env var no setea (local, no en CI)             | `GITHUB_TOKEN=$(gh auth token) goreleaser release ...`                    |
| `template: failed to apply "...GITHUB_REPOSITORY..."` (goreleaser) | Env var no setea                                     | `GITHUB_REPOSITORY=user/repo` añadido al export                            |
| `serve: scheduler fire error (sched X): submit: ...`             | Plugin del schedule no existe en este build            | Verifica con `elsereno plugins list`                                       |
| Dashboard 503 en `/api/v1/scans` o `/schedules`                  | `--scan-store=off` (default)                           | Re-arranca con `--scan-store=memory` o `=db`                              |
| Job `failed` con `scan runner: start run: ...` o `record findings: ...` | Faltan las tablas `runs`/`targets`/`findings` o la base falla | `elsereno db migrate up`; mira el error de Postgres que acompaña      |
| `scanorch: feed: N queued jobs predate this start and will not run` | Jobs en cola de antes de arrancar `serve` (PITF-094)   | Cancélalos (`POST /api/v1/scans/{id}/cancel`) o vuelve a lanzarlos       |
| Audit chain reports `ErrChainBroken`                             | Alguien editó `audit.jsonl` a mano                     | Recovery manual; sin atajo                                                |
| `OCI image runtime: tzdata: cannot find zone "..."`              | Sistema sin tzdata bundle                              | `apt install tzdata` o equivalente                                        |
| `elsereno serve: scheduler exited: ...`                          | Bug del scheduler, reportar issue                     | Captura stderr + abre issue                                               |
| `401`/`403` en `/api/v1/*`                                        | `serve` con OIDC: falta el Bearer JWT o el rol          | Pasa `Authorization: Bearer <jwt>` del emisor configurado en `auth.oidc` |
| `415` / `403` / `421` de `serve`                                   | Cuerpo o `Content-Type` que no es JSON/NDJSON, petición desde otro origen, o `Host` que no es loopback | Manda `-H 'Content-Type: application/json'` (curl `-d` manda form por defecto); llama a `127.0.0.1` o `localhost` (PITF-092) |

---

## 11. Glosario

| Término              | Significado                                                                                    |
|----------------------|------------------------------------------------------------------------------------------------|
| **finding**          | Hallazgo emitido por un plugin (NDJSON v1).                                                    |
| **probe**            | Función `Probe(ctx, target) (Finding, error)` que cada plugin implementa.                      |
| **plugin**           | Implementación de protocolo (modbus, opcua, …); registrado al arrancar via `init()`.            |
| **scope**            | Archivo YAML que limita los targets aceptados. Si presente, targets fuera de scope son `denied`. |
| **vault**            | Almacén cifrado AES-256-GCM con credenciales + master key.                                     |
| **master key**       | Clave derivada de la passphrase del vault con Argon2id. Cifra `creds` y deriva las claves de audit HMAC, backup y CSRF (esta, sin uso). |
| **audit chain**      | Hash chain HMAC en `audit.jsonl`. Cada entry incluye hash del previo.                          |
| **schedule**         | Scan recurrente con cadence (interval o cron) + timezone (v1.75+).                             |
| **scan_jobs**        | Tabla DB que registra jobs de scan-orch (queued/running/completed/failed).                      |
| **scan_schedule_audit** | Tabla DB (v1.84+) que registra eventos sobre schedules: force_overwrite, delete, set_enabled_{true,false}. |
| **scan-store**       | Backend del scan-orch: `off`, `memory`, `db`.                                                  |
| **scan-orch**        | El sub-sistema de orquestación de scans (v1.58+): submit → queue → worker pool → broadcast SSE. |
| **broadcaster**      | Bus SSE intra-proceso; el dashboard se suscribe.                                                |
| **build variant**    | Default / offensive / mini (ver §6).                                                            |
| **triple-confirm**   | `--accept-writes` + `--confirm-target` + `--confirm-token` + vault key (ADR-039).               |
| **goose**            | Library de migraciones DB embebida en el binario via `go:embed`.                                |
| **NDJSON**           | Newline-Delimited JSON: un objeto por línea. Es el formato canónico de finding.                 |
| **SSE**              | Server-Sent Events: stream HTTP unidireccional. `/api/v1/stream` usa esto.                      |
| **CSRF**             | Cross-Site Request Forgery. Sin token: `serve` rechaza las escrituras de otro origen y los cuerpos que no son JSON/NDJSON (PITF-092). |
| **If-Match**         | Header HTTP (v1.78+): optimistic-locking precondition para PUT /schedules/{id}.                 |
| **merge-view**       | Dashboard panel (v1.81+) que muestra el diff cuando un PUT recibe 412.                          |
| **force overwrite**  | PUT sin If-Match (v1.84+ con header `X-Schedule-Force-Overwrite: true`), audita el override.   |
| **PITF**             | Anti-pattern catalogued en `.context/pitfalls.md`.                                              |
| **ADR**              | Architecture Decision Record, en `.context/decisions/`.                                        |

---

---

## 12. `scope.yaml` reference

Un **scope file** limita a qué direcciones y puertos se conecta
elSereno, qué plugins corren y qué números acepta `dial`. Solo se aplica
cuando lo pasas con `--scope FILE`: no hay carga automática (un
`scope.yaml` en el directorio de trabajo o en `~/.elsereno/` no se lee).
Sin `--scope`, no se filtra nada.

Desde el 17-10-2026 lo acepta todo comando que se conecta a un target
(antes solo `scan`, `serve` y `dial`, PITF-095): `scan`, `serve` (scans
del dashboard, la API y los schedules), `discover`, `fingerprint probe`,
`plaintext-check`, `tui --input`, `opcua probe-anon` y `probe-write`,
`s7 probe`, `probe-protection` y `probe-identity` y, en el build
offensive, `write modbus send`, `exploit run`, `proxy listen`, `harvest`
y `creds-check http`, además de `dial validate|batch|wardial` (solo
`blocked_numbers`). `lint --scope` solo valida. Un fichero que no parsea
para el comando con 78.

### Formato

```yaml
version: 1
ranges:                  # direcciones permitidas (IPv4 e IPv6)
  - cidr: 10.0.0.0/24
    note: "planta norte, ticket SOC-12345"
  - cidr: 2001:db8::/48
ports:
  allow: [102, 502, 4840, 20000, 44818, 47808]
  deny: [23]
protocols:               # qué plugins corren
  allow: [modbus, s7, opcua, dnp3, enip, bacnet, banner]
  deny: [s7-exposure]
dial:                    # solo `dial`, build offensive
  blocked_numbers:
    - "34112"            # solo dígitos: sin "+" ni "00" (ver tabla)
```

Cualquier clave fuera de `version`, `ranges`, `ports`, `protocols`,
`binds`, `dial` y `canary` es un error de parseo (`KnownFields`), así
que un typo no pasa en silencio. Cada CIDR es una entrada `cidr` (con
`note` opcional); no hay entradas `host` ni `range`, ni listas
`allow`/`deny` de primer nivel.

### Qué se aplica

| Sección                    | Dónde se aplica                     | Regla                                                                                   |
|----------------------------|-------------------------------------|-----------------------------------------------------------------------------------------|
| `ranges`                   | todo comando de red con `--scope`   | Sin entradas: cualquier dirección. Con entradas: fuera de todas, el target se descarta (o se rechaza con 77 si es el único). |
| `ports.allow`/`ports.deny` | todo comando de red con `--scope`   | `deny` gana. `allow` vacío: cualquier puerto salvo `deny`.                              |
| `protocols.allow`/`protocols.deny` | todo comando que lanza un plugin | Por nombre del plugin o por su protocolo (lo de antes del primer `-`): `s7` cubre `s7` y `s7-exposure`; `s7-exposure` solo ese; `opcuahttps` es un nombre propio. Sin distinguir mayúsculas. `deny` gana; `allow` vacío deja pasar todo lo no denegado, y uno con entradas tiene que incluir `banner` para que corra. |
| `dial.blocked_numbers`     | `dial` (offensive)                  | Bloquea el número exacto y todo lo que empiece por él, además del bloqueo fijo de 3 dígitos o menos. `dial` normaliza el número marcado (quita `+`, `00` inicial y puntuación) pero no la entrada: escríbela solo con dígitos y sin `00` (`"34112"`, no `"+34112"` ni `"0034112"`, que no bloquean nada). |
| `binds`                    | ninguno                             | Se parsea pero no se aplica: un bind no-loopback de `serve` lo controlan sus flags.     |
| `canary`                   | ninguno                             | Se parsea pero no se aplica.                                                            |

Consecuencias que conviene saber:

- Un `scope.yaml` con solo `version: 1` lo deja pasar todo.
- Una CIDR mal escrita (`10.0.0.0/33`) o un puerto fuera de 0..65535 es
  un error al cargar: `lint --scope` y cualquier comando con `--scope`
  salen con 78 (antes se ignoraba en silencio, PITF-097).
- `scan`, `serve`, `discover` y `tui --input` descartan los targets fuera
  de scope antes de cualquier conexión, sin aviso por target ni entrada
  en la auditoría; si no queda ninguno, salen con 66 (`ExitNoInput`).
- Un comando de un solo `--target` lo rechaza con 77 (`ExitNoPerm`) sin
  conectar. Si le das un nombre, lo resuelve una vez, comprueba esa IP y
  se conecta a ella, así que el nombre no puede resolver a otra cosa
  después de la comprobación (`creds-check http` hace lo mismo y deja el
  nombre en la cabecera `Host`).
- `write modbus send`, `exploit run` y `proxy listen` exigen con
  `--scope` una IP:puerto, no un nombre (64): su token de confirmación
  cubre el target tal como lo escribes.
- Un plugin que `protocols` no deja correr: si lo pediste por nombre
  (`--plugin`, o en un job del dashboard), el scan para con 77 o el job
  falla; si no nombraste plugins, se queda fuera y `scan` lo dice en una
  línea por stderr. `discover` no barre los puertos de esos plugins.
- Los verbos cuentan como un plugin: `opcua probe-anon` y `probe-write`
  como `opcua-exposure`, los tres de `s7` como `s7-exposure`, `harvest`
  como su subverbo (`telnet`, `ftp`, `http-basic`, `snmp`),
  `creds-check http` como `http-basic`, `write modbus send` como
  `modbus` y `proxy listen` como su `--plugin`. `exploit run` y
  `plaintext-check` no nombran plugin: solo les aplican rangos y puertos.
- Las familias van por nombre: `deny: [s7]` no cubre `mms`, que también
  habla COTP en el 102; ponlo también. Una entrada que no casa con ningún
  plugin (un typo como `s7-`) no hace nada, y nadie avisa.
- Las sondas HTTP (`harvest http-basic`, `opcuahttps`, `cwmp`, `pbxhttp`,
  `creds-check http`) no siguen redirecciones: un 3xx es la respuesta, no
  una invitación a conectar a otro sitio.
- Con `--scope`, un nombre que no resuelve sale con 68 (y siempre en
  `fingerprint probe`); sin `--scope`, cada comando informa del fallo a su
  manera. Se comprueba la primera dirección del nombre: `localhost` suele
  resolver primero a `::1`, así que un scope con solo `127.0.0.1/32` lo
  rechaza.

### Cómo se usa

```bash
# Validar sin escanear (claves, tipos, CIDR y rango de puertos):
elsereno lint --scope ./fleet-scope.yaml

# Escanear solo lo que el scope permite:
elsereno scan --input list:targets.txt --scope ./fleet-scope.yaml

# El dashboard aplica el mismo scope a todos sus scans:
elsereno serve --scope ./fleet-scope.yaml

# Igual en cualquier comando de red:
elsereno discover --auto 10.0.0.0/24 --scope ./fleet-scope.yaml
elsereno fingerprint probe --plugin modbus --target 10.0.0.5:502 --scope ./fleet-scope.yaml
```

`scan` no tiene modo de prueba: con `--dry-run` se niega a arrancar
(salida 64). Para ver qué quedaría dentro del scope sin tocar nada,
compara la lista de targets con `ranges` y `ports` a mano.

### Best practices

- **Una sesión, un scope**: no recicles `scope.yaml` entre
  ventanas de pen-test. Crear uno fresco por engagement
  evita confusiones.
- **Deja constancia**: quién autorizó, ventana de tiempo y ticket,
  en comentarios YAML o en el `note` de cada rango. Tu futuro yo
  en una investigación post-incidente te lo agradecerá.
- **Modo paranoico**: poner el scope en el repo del SOC
  con git history. PR + review antes de aplicar.

---

## 13. `elsereno.yaml` reference

Config global. Se usa el primer fichero que existe, en este orden
(`internal/config/loader.go`):

1. `--config FILE` flag (si no existe, error).
2. `ELSERENO_CONFIG` env var.
3. `$XDG_CONFIG_HOME/elsereno/elsereno.yaml`, si `XDG_CONFIG_HOME` está
   definida.
4. `~/.config/elsereno/elsereno.yaml`.
5. `~/.elsereno/elsereno.yaml`.
6. `./elsereno.yaml`.

`/etc/elsereno/elsereno.yaml` no se lee (hasta el 17-10-2026 esta lista
lo daba por bueno).

Sin config, todo corre con defaults sensatos (mismo
output que `elsereno config show` con un binario virgen).

### Esqueleto comentado

Son los valores por defecto, tal como los imprime `elsereno config show`
con un binario virgen. Las duraciones se escriben como texto (`30s`,
`2m0s`); un número suelto se rechaza. Cualquier clave que no esté aquí
es un error (`unknown field`, salida 78).

```yaml
retention:
    findings_days: 0
    evidence_days: 0
    runs_days: 0
evidence:
    max_payload_bytes: 16384
scanner:                          # lo leen scan y los scans de serve
    max_concurrent_targets: 100   # targets en paralelo por plugin
    max_concurrent_per_host: 1    # sondas a la vez contra un mismo host
log:
    level: info
    output: stderr
shutdown:
    drain_timeout: 10s
doctor:
    ntp_server: ""
database:                         # lo lee todo comando con DATABASE_URL
    max_conns: 10
    tls_required: auto            # auto | always | disable
web:
    token_ttl_days: 30
    token_generation_cache_ttl: 5s
    rate_limit_per_min_ip: 100
    rate_limit_per_min_token: 300
    max_body_bytes: 1048576
    read_header_timeout: 5s       # los cuatro timeouts los lee serve;
    read_timeout: 30s             # 0 = el valor por defecto, uno
    write_timeout: 30s            # negativo se rechaza
    idle_timeout: 2m0s
readyz:
    audit_tail_entries: 100
exec:
    allowed_paths:
        - /usr/bin
        - /usr/local/bin
        - /opt/homebrew/bin
outbox:
    max_attempts: 10
auth:
    oidc:                         # issuer, audience y jwks_url los lee serve
        issuer: ""
        audience: ""
        jwks_url: ""
        clock_skew: 0s
```

Las claves sin comentario "lo lee" se aceptan pero nada las lee todavía
(cambiarlas no cambia nada): `retention.*`, `evidence.*`, `log.*`,
`shutdown.*`, `doctor.*`, `web.token_*`, `web.rate_limit_*`,
`web.max_body_bytes`, `readyz.*` (solo el stub `audit verify`),
`exec.allowed_paths` (no limita qué binarios se ejecutan),
`outbox.*` y `auth.oidc.clock_skew` (fijo en 60 s en el código).


Hasta el 17-10-2026 un fichero con cualquier duración o lista no
cargaba ("incorrect types", salida 78), tampoco el volcado de
`config show`; y esta sección mostraba claves que no existen (`scan:`,
`scoring:`, `pool_max`...) (PITF-096).

### Validación

```bash
elsereno config lint                        # valida el config efectivo
elsereno config lint --config ./other.yaml  # valida un archivo concreto
```

### Reformatear canónicamente

```bash
elsereno fmt < elsereno.yaml > elsereno.formatted.yaml
```

---

## 14. Schema de finding (NDJSON v1)

Cada línea del output `--output-format ndjson` es un objeto
JSON con esta forma:

```json
{
  "schema": "ndjson:v1",
  "ts": "2026-05-11T12:34:56.123456Z",
  "target": {
    "host": "10.0.0.5",
    "port": 502
  },
  "plugin": "modbus",
  "capability": 60,
  "severity": "high",
  "score": 0.74,
  "factors": [
    { "name": "protocol_risk",   "weight": 0.30, "contribution": 0.25 },
    { "name": "cve_exposure",    "weight": 0.25, "contribution": 0.18 },
    { "name": "confidence",      "weight": 0.20, "contribution": 0.16 },
    { "name": "auth_state",      "weight": 0.15, "contribution": 0.12 },
    { "name": "network_reach",   "weight": 0.10, "contribution": 0.03 }
  ],
  "evidence": {
    "device_id": "Schneider M340 CPU 0x0040",
    "firmware":  "2.61",
    "vendor":    "Schneider Electric",
    "extras": {
      "function_codes": [3, 4, 6, 16, 43]
    }
  },
  "scope_state": "allowed",
  "run_id": "01HW4Z0F5J5K7Q8N9P2R3T4V5W",
  "operator": "alice@soc.local"
}
```

### Campos garantizados

| Campo            | Tipo       | Descripción                                                |
|------------------|------------|------------------------------------------------------------|
| `schema`         | string     | Siempre `ndjson:v1` mientras estás en v1.                  |
| `ts`             | string     | RFC3339 con μs (UTC). Timestamp de emisión.                |
| `target.host`    | string     | IPv4/IPv6/hostname.                                        |
| `target.port`    | int        | 1-65535.                                                   |
| `plugin`         | string     | Nombre del plugin que generó el finding.                   |
| `capability`     | int        | 0-100. Confianza del fingerprint.                          |
| `severity`       | string     | `critical` / `high` / `medium` / `low` / `info`.           |
| `score`          | float      | 0.0-1.0. ADR-006 weighted sum de factors.                  |
| `factors`        | array      | Lista de `{name, weight, contribution}` (ver §13).         |
| `evidence`       | object     | Bytes / metadata específicos del plugin.                   |
| `scope_state`    | string     | `allowed` / `denied`.                                      |
| `run_id`         | string     | ULID que agrupa todos los findings de un mismo run.        |
| `operator`       | string     | Identidad que disparó el scan.                             |

### Reglas de evolución

- **Campos sólo se añaden**. Nunca se rompe el shape v1 sin
  bump a `ndjson:v2`.
- **Order no garantizado** dentro del objeto (JSON), pero sí
  entre líneas (un finding por target+port en el orden de
  emisión del probe).
- **Bytes binarios** dentro de `evidence` van como
  hex-encoded strings (campo `_hex`) o base64 con `_b64`
  según el plugin. Documentado en `docs/protocols/<plugin>.md`.

### Pipelines útiles

```bash
# Filtrar por severidad:
elsereno scan ... | jq -c 'select(.severity == "high" or .severity == "critical")'

# Extraer solo host+port+plugin:
elsereno scan ... | jq -r '[.target.host, .target.port, .plugin] | @tsv'

# Agrupar por plugin (necesitas todo en memoria):
elsereno scan ... | jq -s 'group_by(.plugin) | map({plugin: .[0].plugin, count: length})'

# Convertir a CSV (jq-fu):
elsereno scan ... | jq -r '[.ts,.target.host,.target.port,.plugin,.severity,.score] | @csv'
```

---

## 15. HTTP API reference

El dashboard expone `/api/v1/*`. Sin OIDC (modo dev, que
`serve` solo admite en loopback) no piden autenticación: el
operador va en la cabecera opcional `X-Operator`. Con
`auth.oidc` configurado (obligatorio fuera de loopback), las rutas
con rol piden `Authorization: Bearer <JWT>` (401 sin token, 403 con
rol insuficiente); `/`, `/admin/security`, `/metrics`, `/healthz`,
`/readyz` y los `GET` de `plugins`, `scoring`, `health`,
`health/pool` y `openapi.yaml` siguen abiertos. No hay
cookie ni token CSRF. En su lugar, `serve` rechaza lo que una página del navegador podría mandarle sin que
lo quieras (desde el 17-10-2026, PITF-092): con bind en loopback, un
`Host` que no sea un nombre de loopback (421, DNS rebinding); las
escrituras (todo salvo GET, HEAD y OPTIONS) desde otro origen según
`Origin` o `Sec-Fetch-Site` (403); y las escrituras cuyo cuerpo o
`Content-Type` no sea JSON o NDJSON (415): una escritura sin cuerpo no
lleva `Content-Type`, o lleva uno de esos dos. El CLI y curl con JSON o
NDJSON no mandan `Origin` y pasan. Responden con `Content-Type:
application/json` (excepto SSE).

### Scans

| Método | Path                                    | Qué hace                                               |
|--------|-----------------------------------------|--------------------------------------------------------|
| POST   | `/api/v1/scans`                         | Crea un scan job (body: SubmitRequest).                |
| POST   | `/api/v1/scans/bulk`                    | Crea varios jobs en una sola request (v1.69+).         |
| GET    | `/api/v1/scans`                         | Lista los últimos N jobs.                              |
| GET    | `/api/v1/scans/{id}`                    | Detalle de un job y sus contadores (sus findings, en `/api/v1/findings`). |
| POST   | `/api/v1/scans/{id}/cancel`             | Cancela un job en cola o en curso; uno en curso deja de abrir conexiones en un segundo como mucho. |

### Schedules (v1.70+)

| Método | Path                                          | Qué hace                                                |
|--------|-----------------------------------------------|---------------------------------------------------------|
| POST   | `/api/v1/schedules`                           | Crea un schedule (interval o cron).                     |
| GET    | `/api/v1/schedules`                           | Lista todos los schedules.                              |
| GET    | `/api/v1/schedules/{id}`                      | Uno solo.                                               |
| PUT    | `/api/v1/schedules/{id}`                      | Edita un schedule (v1.74+); soporta `If-Match` v1.78+.  |
| DELETE | `/api/v1/schedules/{id}`                      | Borra; escribe audit `delete` event (v1.88+).           |
| POST   | `/api/v1/schedules/{id}/enable`               | Toggle on; audit `set_enabled_true` (v1.88+).           |
| POST   | `/api/v1/schedules/{id}/disable`              | Toggle off; audit `set_enabled_false` (v1.88+).         |
| POST   | `/api/v1/schedules/preview?count=N`           | Preview de los próximos N fires (v1.77+; cap 10 v1.79+).|
| GET    | `/api/v1/schedules/{id}/audit`                | Audit history del schedule (v1.84+).                    |
| DELETE | `/api/v1/schedules/audit?before=<rfc3339>`    | Prune audit log global (v1.86+).                        |
| GET    | `/api/v1/schedules/export?format=`            | Backup en `json`, `ndjson`, `csv` o `ics` (v1.97+).     |
| POST   | `/api/v1/schedules/import?on_conflict=`       | Restaura NDJSON o un array JSON (v1.99+). Cada fila conserva su `"enabled"`; sin él se crea desactivada (PITF-094). `on_conflict=skip\|overwrite\|rename`. |

### Findings + Runs + Triage

| Método | Path                              | Qué hace                                                |
|--------|-----------------------------------|---------------------------------------------------------|
| GET    | `/api/v1/findings`                | Findings paginados (`?page=`, `?limit=`, filtros).     |
| GET    | `/api/v1/findings/diff`           | Diff entre dos runs (`?old=<run_id>&new=<run_id>`).     |
| GET    | `/api/v1/runs`                    | Runs históricos.                                        |
| GET    | `/api/v1/triage`                  | Counts por bucket (quick-win / strategic / utility / routine). |

### Audit + Cadence

| Método | Path                              | Qué hace                                                |
|--------|-----------------------------------|---------------------------------------------------------|
| GET    | `/api/v1/audit`                   | Audit log entries (paginadas).                          |
| GET    | `/api/v1/audit/cadence`           | Series temporales: `proxy_allowlist_reload` por día.    |

### Inputs + plugins + scoring

| Método | Path                              | Qué hace                                                |
|--------|-----------------------------------|---------------------------------------------------------|
| GET    | `/api/v1/inputs/preview`          | Preview de input source (`?kind=list:F`, etc).          |
| GET    | `/api/v1/plugins`                 | Lista plugins compilados (v1.68+).                      |
| GET    | `/api/v1/scoring`                 | Weights + thresholds (mismo output que `elsereno scoring`). |
| GET    | `/api/v1/health`                  | Health endpoint (sin auth).                             |
| GET    | `/healthz`                        | Health simple, sin auth, para load balancers.            |
| GET    | `/readyz`                         | Readiness check.                                        |
| GET    | `/api/v1/openapi.yaml`            | Spec OpenAPI 3.1 emitido del código.                    |

### Streaming (SSE)

| Método | Path                | Eventos                                                                                  |
|--------|---------------------|------------------------------------------------------------------------------------------|
| GET    | `/api/v1/stream`    | `finding`, `run_start`, `run_end`, `scan_state_change`, `scan_stats_progress`, … (v1.63+) |

### Ejemplo: crear un schedule via curl

```bash
# Modo dev (loopback, sin OIDC). Con OIDC, añade
#   -H "Authorization: Bearer $JWT"
curl -X POST http://127.0.0.1:8787/api/v1/schedules \
    -H "X-Operator: alice" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "weekday-modbus-09am-ny",
      "template": {"input": "list:/etc/elsereno/fleet.txt", "plugins": ["modbus"]},
      "cron_expr": "0 9 * * 1-5",
      "timezone": "America/New_York"
    }'
```

---

## 16. Plugins por protocolo

Lista del build default: **35 plugins** registrados, 32 en el barrido
por defecto (`discover` / `scan`) más 3 sondas opt-in que solo corren
nombradas con `--plugin` (`s7-exposure`, `opcua-exposure`,
`codesys-active`). La fuente autoritativa es `elsereno plugins list`
sobre tu binario. La columna Status sale del código: **RO + WG** son
los 18 protocolos que `elsereno-offensive proxy listen --plugin` sabe
servir con write-gate (verificado 2026-10-07 contra el despacho de
`cmd/elsereno/cmd_proxy_offensive.go`). `offensive/write/` contiene además
código gated para atg, dlms, fox, hartip, iec104, knxip y mbustcp que
ningún comando conecta todavía; esos figuran como RO.

| Plugin       | Puerto(s)         | Familia                                                               | Status   |
|--------------|-------------------|-----------------------------------------------------------------------|----------|
| `atg`        | TCP/10001         | ATG Veeder-Root TLS-350/4 (gasolinera tank monitor)                   | RO       |
| `atmodem`    | (modem)           | AT modem Hayes/GSM/EN 81-28                                           | RO       |
| `bacnet`     | UDP/47808         | BACnet/IP (HVAC, edificios)                                            | RO + WG  |
| `banner`     | (cualquiera)      | TCP banner grab (fallback)                                            | RO       |
| `codesys`    | TCP/1217          | CoDeSys V3 (Wago/Beckhoff alt/Schneider M251/Eaton/Bosch Rexroth)     | RO + WG  |
| `codesys-active` | opt-in, sin puerto (usar contra 1217) | CoDeSys V3: sonda activa channel-open; confirma por una trama Block Driver (un banner CoDeSys cuenta, con nota) | RO (opt-in) |
| `cwmp`       | TCP/7547          | TR-069 CWMP ACS (FreeACS, GenieACS, Nokia, etc.)                       | RO + WG  |
| `dlms`       | TCP/4059          | DLMS/COSEM (IEC 62056-46 smart meters)                                 | RO       |
| `dnp3`       | TCP/20000         | DNP3 IEEE 1815 (power/water utility)                                  | RO + WG  |
| `enip`       | TCP/44818         | EtherNet/IP CIP (Rockwell, Allen-Bradley, Omron)                       | RO + WG  |
| `finsudp`    | UDP/9600          | Omron FINS (CJ/CS/CP/NJ/NX)                                            | RO + WG  |
| `fox`        | TCP/1911 + 4911   | Niagara Fox (Tridium, edificios)                                       | RO       |
| `gesrtp`     | TCP/18245         | GE-SRTP (GE Fanuc, Emerson PACSystems, Series 90)                      | RO + WG  |
| `hartip`     | UDP/5094          | HART-IP (process instrumentation)                                      | RO       |
| `iax2`       | UDP/4569          | Asterisk IAX2 (PBX)                                                   | RO + WG  |
| `iec104`     | TCP/2404          | IEC 60870-5-104 (power SCADA)                                          | RO       |
| `knxip`      | UDP/3671          | KNXnet/IP (BAS / edificios)                                            | RO       |
| `mbustcp`    | TCP/10001         | M-Bus over TCP (smart meters water/gas/heat)                          | RO       |
| `melsoft`    | TCP/5007          | Mitsubishi MELSOFT (GX Works, puerto de comunicación MELSOFT de la CPU) | RO       |
| `mms`        | TCP/102           | IEC 61850 MMS (substation protection)                                  | RO + WG  |
| `modbus`     | TCP/502           | Modbus/TCP (PLC + RTU industrial generalista)                          | RO + WG  |
| `mqtt`       | TCP/1883 (8883 TLS) | MQTT broker (CONNECT anónimo, suscripción wildcard, Sparkplug B)    | RO       |
| `opcua`      | TCP/4840          | OPC UA TCP                                                            | RO + WG  |
| `opcua-exposure` | opt-in, sin puerto (usar contra 4840) | OPC UA: sesión anónima + walk de tags escribibles               | RO (opt-in) |
| `opcuahttps` | TCP/4843          | OPC UA HTTPS (binding Part 6): GetEndpoints + postura de seguridad    | RO + WG  |
| `pbxhttp`    | TCP/443/80/8088   | HTTP admin pages PBX (FreePBX, 3CX, Yeastar, etc.)                     | RO + WG  |
| `pcworx`     | TCP/1962          | Phoenix Contact PCWorx (ILC + AXC F + RFC)                             | RO + WG  |
| `proconos`   | TCP/20547         | KW-Software ProConOS                                                  | RO       |
| `redlion`    | TCP/789           | Red Lion Crimson v3 / CR3 (HMIs/RTUs)                                  | RO + WG  |
| `s7`         | TCP/102           | Siemens S7comm                                                        | RO + WG  |
| `s7-exposure` | opt-in, sin puerto (usar contra 102) | S7: nivel de protección + identidad vía SZL                          | RO (opt-in) |
| `sip`        | UDP/5060          | SIP / PBX                                                             | RO + WG  |
| `slmp`       | TCP/5007          | Mitsubishi MELSEC SLMP                                                | RO + WG  |
| `twincat`    | TCP/48898         | Beckhoff TwinCAT ADS                                                  | RO       |
| `xot`        | TCP/1998 / 5555   | X.25 over TCP (RFC 1613), legacy banking/airline                     | RO       |

**Leyenda:** `RO` = read-only (default build); `WG` = write-gated
proxy disponible en offensive build con triple-confirm.

Notas por protocolo: cada plugin tiene su archivo en
[`docs/protocols/<name>.md`](protocols/) con detalles del wire
protocol, byte-level details del fingerprint, y las CVEs
relevantes (cuando `cve_exposure` está mapeado).

---

## 17. Offensive build

El binario `elsereno-offensive` (build tag `offensive`)
añade **escrituras gateadas** y otras superficies activas
sobre el binario default. Cada acción ofensiva requiere
una secuencia de confirmaciones (ADR-039) para impedir
disparos accidentales.

### Triple-confirm fence

Todas las operaciones de escritura/explote requieren:

1. `--accept-writes` (flag explícito en la CLI).
2. `--confirm-target <ip>:<port>` (confirma que sabes a
   qué estás disparando, fail-fast en typos).
3. `--confirm-token <STRING>` (string mostrado en el log
   de inicio para confirmar que estás viendo la sesión
   correcta).
4. **Vault desbloqueado**: el audit HMAC se firma con la
   master key. Si está locked, la operación se rechaza.

### Ejemplo: write Modbus

```bash
# 1) Build offensive (binary aparte, con el build-tag):
go build -tags offensive -o elsereno-offensive ./cmd/elsereno

# 2) Mint del confirm-token para la sesión (dry-run):
#    allowlist = FC 6 sobre unit 1, registros 100..200.
elsereno-offensive write modbus proxy-dry-run \
    --target 10.0.0.5:502 \
    --write "unit=1;fc=6;start=100;end=200" \
    --vault-passphrase-file ~/.elsereno/dev.pp
#    -> imprime PayloadHash y, con el passphrase, el Confirm-token.

# 3) Arranca el proxy write-gated con ese token:
elsereno-offensive proxy listen --plugin modbus \
    --listen 127.0.0.1:5020 \
    --target 10.0.0.5:502 \
    --write "unit=1;fc=6;start=100;end=200" \
    --accept-writes \
    --confirm-target 10.0.0.5:502 \
    --confirm-token "<TOKEN-del-paso-2>" \
    --vault-passphrase-file ~/.elsereno/dev.pp
```

El proxy:
- Acepta el handshake del cliente Modbus.
- Forwardea reads (FC 1-4) sin filtrar.
- Para writes (FC 5/6/15/16/22/23): aplica el allowlist por
  `(unit, FC, rango-de-direcciones)`. Match → forward. Miss →
  excepción IllegalFunction (0x01) + audit entry; upstream no lo ve.
- Para FC 8 (Diagnostics) gatea por sub-función: lecturas/contadores
  pasan; las mutantes (Force Listen Only 0x04 = DoS, Clear Counters
  0x0A, Restart 0x01, ...) se deniegan por defecto. Para autorizar una
  concreta añade `--diag-subfunction 0x04` (repetible) **tanto al
  dry-run como al proxy**: queda atada al confirm-token.

El allowlist round-trip a YAML con `--emit-allow-file` (claves
`writes:` y `diag_subfunctions:`); luego `proxy listen --allow-file
<path>`. Demo end-to-end con simulador: `scripts/demo-modbus-proxy.sh`.

### Dial / SMS

Disponible sólo en offensive. Hoy ningún comando marca ni envía
SMS: `dial validate` valida un número, y `dial batch` y `dial wardial`
validan, clasifican y auditan listas; la entrega por hardware es vNext. El
flag `--dial-allowed` no existe todavía: es la puerta prevista para
el primer comando que marque. Números ≤3 dígitos están **bloqueados
duro** (evita marcar 911, emergency, asistencia operador, etc.).

### Audit obligatorio

Cada escritura ofensiva produce en el audit log:
- `offensive_write` con todos los parámetros + hash del
  payload.

(El catálogo tiene un tipo `scope_applied`, pero nada lo emite: las
escrituras ofensivas no pasan por el scope.)

`elsereno audit verify-file` debe completar exit-0 después.
Si reportes diff con un blue-team el archivo `audit.jsonl`
es la evidencia oficial.

---

## 18. Deployment

### systemd unit (Linux)

Crear `/etc/systemd/system/elsereno.service`:

```ini
[Unit]
Description=ElSereno ICS/OT exposure dashboard
Documentation=https://github.com/RobinR00T/elSereno
After=network-online.target postgresql.service
Wants=network-online.target

[Service]
Type=exec
User=elsereno
Group=elsereno
ExecStart=/usr/local/bin/elsereno serve \
    --addr 127.0.0.1:8787 \
    --scan-store=db \
    --scan-pool 8 \
    --audit-retention-days 90 \
    --vault-passphrase-file /etc/elsereno/vault.pp
EnvironmentFile=/etc/elsereno/environment
Restart=on-failure
RestartSec=5

# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=true
LockPersonality=true
RestrictRealtime=true
MemoryDenyWriteExecute=true
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
CapabilityBoundingSet=
AmbientCapabilities=
ReadWritePaths=/var/lib/elsereno /var/log/elsereno
StateDirectory=elsereno
LogsDirectory=elsereno
ConfigurationDirectory=elsereno

[Install]
WantedBy=multi-user.target
```

`/etc/elsereno/environment` (mode 0640, root:elsereno):

```bash
DATABASE_URL=postgres://elsereno@/elsereno?host=/var/run/postgresql&sslmode=disable
ELSERENO_CONFIG=/etc/elsereno/elsereno.yaml
ELSERENO_LOG_LEVEL=info
```

Activar:

```bash
sudo useradd -r -s /usr/sbin/nologin elsereno
sudo install -d -m 0750 -o elsereno -g elsereno /var/lib/elsereno /var/log/elsereno /etc/elsereno
sudo install -m 0600 -o elsereno -g elsereno vault.pp /etc/elsereno/vault.pp
sudo systemctl daemon-reload
sudo systemctl enable --now elsereno.service
sudo systemctl status elsereno
```

Logs: `journalctl -u elsereno -f`.

### Docker / OCI

Para `docker compose`:

```yaml
# compose.prod.yml
services:
  elsereno:
    image: ghcr.io/robinr00t/elsereno:1.88.0
    restart: unless-stopped
    network_mode: host    # o expone puertos: 127.0.0.1:8787:8787
    environment:
      DATABASE_URL: postgres://elsereno:****@db:5432/elsereno?sslmode=require
    volumes:
      - ./vault.pp:/etc/elsereno/vault.pp:ro
      - elsereno-state:/var/lib/elsereno
    command:
      - serve
      - --scan-store=db
      - --audit-retention-days=90
      - --vault-passphrase-file=/etc/elsereno/vault.pp
    healthcheck:
      test: ["CMD", "curl", "-fsS", "http://localhost:8787/healthz"]
      interval: 30s
      timeout: 5s
      retries: 3

volumes:
  elsereno-state:
```

### Kubernetes (snippet mínimo)

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: elsereno
spec:
  replicas: 1
  selector: { matchLabels: { app: elsereno } }
  template:
    metadata: { labels: { app: elsereno } }
    spec:
      serviceAccountName: elsereno
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        seccompProfile: { type: RuntimeDefault }
      containers:
        - name: elsereno
          image: ghcr.io/robinr00t/elsereno:1.88.0
          args:
            - serve
            - --scan-store=db
            - --audit-retention-days=90
            - --vault-passphrase-file=/etc/elsereno/vault.pp
          env:
            - name: DATABASE_URL
              valueFrom: { secretKeyRef: { name: elsereno-db, key: url } }
          volumeMounts:
            - name: vault-passphrase
              mountPath: /etc/elsereno
              readOnly: true
          ports:
            - { containerPort: 8787, name: http }
          livenessProbe:
            httpGet: { path: /healthz, port: 8787 }
          readinessProbe:
            httpGet: { path: /readyz, port: 8787 }
          securityContext:
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
            capabilities: { drop: ["ALL"] }
            runAsNonRoot: true
            runAsUser: 1000
          resources:
            requests: { cpu: 200m, memory: 128Mi }
            limits:   { cpu: 1000m, memory: 512Mi }
      volumes:
        - name: vault-passphrase
          secret:
            secretName: elsereno-vault-passphrase
            defaultMode: 0400
```

Sin réplicas múltiples por ahora: el Scheduler asume
single-process; multi-replica race el carryover v1.90+
(advisory lock).

### Detrás de un proxy inverso

No: `serve` en loopback detrás de Nginx u otro proxy deja expuesto a la
red el modo dev, que no autentica, y la guarda contra peticiones de otras
webs lo rechaza (421 por el `Host` público, 403 por el `Origin`). Para
servir fuera de loopback, `serve` hace TLS por su cuenta y exige OIDC:
`--addr 0.0.0.0:8443 --tls-cert ... --tls-key ... --i-know-what-im-doing`
con `auth.oidc` configurado.

---

## 19. Shell completion + man pages

### Bash / zsh / fish completions

Todavía no hay: `elsereno completion` es un stub que sale con 75
("planned for a later phase"). Mientras tanto, `elsereno --help` y
`elsereno <verbo> --help` listan verbos y flags.

### Man pages

Las páginas vienen ya generadas en el repo y en el tarball de release
por defecto (`man/man1`, `man/man5`, `man/man7`; el tarball mini solo
lleva `elsereno.1`). `elsereno gen-man` es
un stub; para regenerarlas desde las fuentes Markdown hace falta
`pandoc`:

```bash
scripts/gen-manpages.sh                # escribe man/man{1,5,7}/

# Instalar (Linux):
sudo cp man/man1/*.1 /usr/local/share/man/man1/
sudo cp man/man5/*.5 /usr/local/share/man/man5/
sudo cp man/man7/*.7 /usr/local/share/man/man7/
sudo mandb

# Consultar:
man elsereno
man elsereno-scope        # sección 5: scope.yaml
man elsereno.yaml         # sección 5: configuración
man elsereno-security     # sección 7: modelo de seguridad
```

El paquete `elsereno` (`.deb` / `.rpm` / `.apk`) instala `elsereno(1)`
bajo `/usr/share/man/man1/`; los paquetes offensive y mini no instalan
páginas man, y las de las secciones 5 y 7 solo van en el tarball.

---

## 20. Backup & disaster recovery

### Lo que hace `backup` hoy (y lo que no)

`elsereno backup create` guarda **solo `vault.v1.bin`**, cifrado con
una clave que se deriva de la master del propio vault. Por eso un
backup solo se puede restaurar donde ese mismo vault sigue existiendo
(comprobado el 17-10-2026): en una máquina sin vault, `backup restore`
sale con 64 ("vault not initialised"), y con un vault nuevo creado con
la misma passphrase falla con "wrong key", porque la sal es otra. No
sirve, por tanto, para recuperarse de perder el vault, que es justo
cuando haría falta. Cambiarlo exige un formato de backup nuevo
(decisión abierta en TODO-vNext, PITF-093).

`audit.jsonl` y `elsereno.yaml` **no** van en el backup, ni las tablas
de Postgres (`scan_jobs`, `scan_schedules`...), que tienen su propio
`pg_dump`.

### Recuperación que sí funciona hoy

`vault.v1.bin` ya va cifrado con tu passphrase (Argon2id + AES-GCM) y
lleva dentro su sal: copiado a otra máquina, se desbloquea con la misma
passphrase. Copia el fichero tal cual, junto con el resto, a un
almacenamiento separado:

```bash
#!/usr/bin/env bash
set -euo pipefail
DEST=/var/backups/elsereno/$(date -u +%Y%m%dT%H%M%S)
install -d -m 0700 "$DEST"
install -m 0600 ~/.elsereno/vault.v1.bin "$DEST/"
# La config, de donde la lee elSereno (orden de §13):
for c in "${ELSERENO_CONFIG:-}" "${XDG_CONFIG_HOME:-$HOME/.config}/elsereno/elsereno.yaml" \
         "$HOME/.config/elsereno/elsereno.yaml" "$HOME/.elsereno/elsereno.yaml"; do
  if [ -n "$c" ] && [ -e "$c" ]; then install -m 0600 "$c" "$DEST/elsereno.yaml"; break; fi
done
# audit.jsonl no existe hasta que algo escribe en él (los verbos del
# build offensive o `audit serve`):
if [ -e ~/.elsereno/audit.jsonl ]; then install -m 0600 ~/.elsereno/audit.jsonl "$DEST/"; fi
find /var/backups/elsereno -mindepth 1 -maxdepth 1 -mtime +30 -exec rm -rf {} +
```

Un fichero que no existe se salta a propósito; cualquier otro fallo
(permisos, disco lleno) para el script.

Para restaurar en una máquina nueva: pon `vault.v1.bin` en
`~/.elsereno/` (0600), `audit.jsonl` y la configuración en su sitio, y
comprueba con `elsereno vault status`, `elsereno creds list` (pide la
passphrase) y `elsereno audit verify-file`.

**Restore drill**: cada trimestre, en una máquina limpia, restaura así y
abre el vault con la passphrase; es la única prueba de que no se ha
perdido.

---

## 21. Performance tuning

### Worker pool

```
elsereno serve --scan-pool N    # clamped [1, 64]
```

- **Default**: 2 (conservador para no saturar la red al
  arrancar).
- **Recomendado**: `nproc - 2` o el throughput de tu link
  upstream / 50 (cada scan target es ~10-20 KB/s pico).
- **Máximo útil**: 64 (clamp). Más allá los kernel-level
  socket budgets dominan.

### `scanner` (concurrencia de cada scan)

```yaml
scanner:
  max_concurrent_targets: 32
  max_concurrent_per_host: 1
```

Distinto del worker pool: limita cuántos targets puede
tener un scan en vuelo (por plugin) y cuántas sondas a la
vez recibe un mismo host. Lo leen `scan` (`--max-concurrent`
lo sobreescribe) y, desde el 17-10-2026, los scans de
`serve`. El worker pool limita cuántos scans simultáneos
ejecuta serve.

### Postgres connection pool

```yaml
database:
  max_conns: 10
```

A nivel binario. La DB también tiene su `max_connections`
(default 100 en pg 16); deja margen para `--scan-pool`
más el dashboard.

### Garbage collection

Default GOGC=100 va bien para findings hasta ~10k/min. Si
tu deployment los excede:

```bash
GOGC=200 elsereno serve ...    # menos GC pauses, más RSS
GOMEMLIMIT=512MiB elsereno serve ...    # hard cap (Go 1.19+)
```

### Profiling on-demand

```bash
# pprof endpoints (default off; activa con flag):
ELSERENO_DEBUG_PPROF=1 elsereno serve ...
curl http://127.0.0.1:8787/debug/pprof/heap > heap.pprof
go tool pprof -http=:9090 heap.pprof
```

(El endpoint pprof sólo escucha con la env var explícita
para no leak metadata en deploy normal.)

---

## 22. FAQ rápida

**¿Necesito Postgres?**
No para `scan` / `discover` / lotes, el binario es
stateless. Sí si quieres que el dashboard (`serve`) recuerde
scans/schedules tras reinicio (`--scan-store=db`).

**¿Funciona contra IPv6?**
Sí desde v1.14. `targets.txt` acepta IPv6 entre brackets:
`[2001:db8::5]:502`.

**¿Tiene rate-limiting per-target?**
No nativo. `scanner.max_concurrent_targets` y
`scanner.max_concurrent_per_host` (1 por defecto: nunca dos
sondas a la vez contra un host) evitan el peor caso. Para
rate-limiting estricto en networks frágiles, integra con
un FRR/`tc` rule a nivel host.

**¿Puede mandar findings directos a Splunk / SIEM?**
No nativo (todavía). El patrón canónico es: scan →
NDJSON file → forwarder. Ver [`docs/INTEGRATIONS.md`](INTEGRATIONS.md).

**¿Funciona en Windows?**
No actualmente. Bloqueador: `syscall.*` por-plataforma en
`internal/audit` (file locking) + sandboxing. Item v1.x
en TODO-vNext.md.

**¿Soporta autenticación OIDC?**
No actualmente. Single-operator por proceso. Item vNext.

**¿Cómo se renueva el master del vault?**
`elsereno vault rotate` (planeado). De momento un backup no sirve
(se descifra con la master vieja): hay que crear un vault nuevo y
volver a guardar cada credencial. Receta en la FAQ, "¿Puedo cambiar
la passphrase del vault?".

**¿Puedo correr múltiples `serve` contra la misma DB?**
v1.88 sólo soporta single-process Scheduler. v1.90+
añadirá advisory lock pruner. Para alta-disponibilidad
hoy, usa un único serve activo + replicas read-only del
DB.

**Olvido la passphrase del vault**
Sin recuperación. Borra `vault.v1.bin`, re-init con nueva
passphrase, vuelve a guardar credenciales. La master del
vault está derivada con Argon2id + sin escape-hatch a
propósito.

**¿Funciona offline / air-gapped?**
Sí. Tarball + paquete `.deb`/`.rpm` no requiere conexión a
internet en runtime salvo para las APIs de input externas
(Shodan/Censys/etc). Para air-gap real, usa `list:` o
`nmap:` como input.

**¿Cómo verifico la integridad del binario instalado?**
`shasum -a 256 -c checksums.txt` (provisto en cada
release). Y `gpg --verify` con la clave pública del
mantenedor (`ACE3B86BACACE7D6`).

---

## Más documentación

- [`INSTALL.md`](../INSTALL.md), instalación detallada con
  todos los paquetes y SBOM verification.
- [`README.md`](../README.md), overview + Quickstart.
- [`docs/DEV-SETUP.md`](DEV-SETUP.md), workflow de
  desarrollo (clonar repo, scripts/bootstrap.sh, scripts/start.sh).
- [`docs/SECURITY.md`](SECURITY.md), modelo de seguridad,
  threat model, hardening checklist.
- [`docs/INTEGRATIONS.md`](INTEGRATIONS.md), SIEM /
  observability recipes (Splunk, Elastic, Loki, Prometheus).
- [`docs/OPERATIONS.md`](OPERATIONS.md), runbooks
  operacionales: release flow, Dependabot policy, post-public-
  flip checklist, troubleshooting CI, admin handoff.
- [`docs/FAQ.md`](FAQ.md), preguntas frecuentes
  expandidas.
- [`docs/ARCHITECTURE.md`](ARCHITECTURE.md), diseño
  interno.
- [`docs/openapi.yaml`](openapi.yaml), spec de la API.
- [`docs/protocols/`](protocols/), engineering notes por
  protocolo.
- [`docs/exposure-auditing.md`](exposure-auditing.md): guía de las
  probes de exposición read-only (S7, OPC UA, plaintext-check,
  creds-check) y su trazabilidad al NIST SP 800-82 r4.
- [`docs/parser-validation.md`](parser-validation.md): estado de
  validación de cada parser de protocolo (captura real vs fixture).
- [`docs/standards/nist-sp800-82r4.md`](standards/nist-sp800-82r4.md):
  mapeo de detecciones a vulnerabilidades del estándar.
- [`docs/manual/elsereno-manual.md`](manual/elsereno-manual.md)
manual narrativo histórico (casos de uso con detalle).
- `.context/`: internal context (state, decisions,
  pitfalls). Lectura recomendada antes de modificar
  código.

¿Algo no cubre este manual? Abre un issue o expande la
sección directamente, es markdown vivo.
