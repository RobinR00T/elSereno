# ElSereno — FAQ expandida

Preguntas frecuentes con respuestas detalladas. Para
preguntas rápidas con un párrafo de respuesta, ver el
[§22 del MANUAL.md](MANUAL.md#22-faq-rápida).

---

## Instalación

### ¿Qué binario instalo: default, offensive o mini?

- **default** (`elsereno`): el 90% de los casos. Scan
  read-only, dashboard, TUI, 28 plugins. Lo que querés si
  no sabes cuál elegir.
- **offensive** (`elsereno-offensive`): SÓLO si haces
  pen-test autorizado con escrituras a ICS. Activa los
  proxies write-gated con triple-confirm.
- **mini** (`elsereno-mini`): hosts embedded / jump-hosts
  donde no necesitás el dashboard ni TUI y quieres menos
  superficie de ataque. Excluye `serve` / `api` / `tui`.

Default + offensive pueden coexistir en el mismo host
(binarios distintos). Mini es excluyente.

### ¿Necesito root para instalar?

Sólo para escribir en `/usr/local/bin/` (`sudo install`) o
crear el systemd service. El binario en sí corre como un
usuario sin privilegios — sólo necesita `cap_net_bind_service`
si quiere bindear puertos <1024:

```bash
sudo setcap cap_net_bind_service=+ep /usr/local/bin/elsereno
```

### ¿Es portable a Windows?

**Aún no**. Bloqueadores:

- `syscall.*` por-plataforma en `internal/audit` (file
  locking via flock — usaríamos `LockFileEx` en Windows).
- Sandboxing (Windows usaría AppContainer / Job Objects en
  lugar de seccomp).

Item en `TODO-vNext.md`. Si quieres priorizarlo, abre un
issue.

### ¿Funciona offline / air-gapped?

Sí. El tarball + paquete `.deb`/`.rpm` no requiere conexión
a internet en runtime salvo para las APIs de input externas
(Shodan/Censys/etc). Para air-gap real, usa `--input list:` o
`--input nmap:` como fuente de targets.

### ¿Cómo verifico la integridad del binario?

Cada release incluye `checksums.txt` + GPG signature en
la tag:

```bash
# Checksum del binario:
shasum -a 256 -c checksums.txt

# Firma del tag:
git tag -v v1.88.0
# → "Good signature from Daniel Solís Agea <daniel.solis@zynap.com>"

# SBOM (lista de dependencias Go):
jq '.metadata.component.version' elsereno_*_cyclonedx.json
```

Más info en [SECURITY.md §7](SECURITY.md#7-supply-chain).

---

## Vault y secretos

### Olvidé la passphrase del vault. ¿Cómo recupero?

**No hay recuperación**. El vault se cifra con scrypt-derived
key — sin la passphrase, el vault es bytes random.
Sin escape-hatch a propósito (PITF-021).

Opciones:

1. Si tienes un backup reciente y **conoces su passphrase**:
   `elsereno backup restore`.
2. Si no: `rm ~/.elsereno/vault.v1.bin`, `vault init` con
   nueva passphrase, `creds store` re-importar cada
   credencial manualmente.

### ¿Puedo cambiar la passphrase del vault?

En v1.88 no hay verbo dedicado (`vault rotate` está en
vNext). De momento:

```bash
elsereno vault unlock                         # con passphrase vieja
elsereno backup create --output /tmp/old.tar.gz.enc
mv ~/.elsereno/vault.v1.bin ~/.elsereno/vault.v1.bin.old
elsereno vault init                           # con passphrase nueva
elsereno backup restore --input /tmp/old.tar.gz.enc --to /tmp/r
# ... y re-importas las creds una a una con `creds store`.
```

Workaround feo, lo sé. PR welcome.

### ¿Por qué `creds store --plaintext '<api-key>'` no funciona?

Intencional. PITF-032: secrets en argv son visibles en
`ps -ef`. La forma correcta es leer de stdin:

```bash
echo "$YOUR_KEY" | elsereno creds store --name shodan_api_key
# o más elegante:
read -s -r KEY && echo "$KEY" | elsereno creds store --name shodan_api_key
unset KEY
```

### ¿Cómo expongo una credencial a otro proceso?

`creds show --reveal --name shodan_api_key` imprime el
plaintext a stdout **y audita el reveal**. Pipe a un
archivo 0600 si necesitas persistirlo para un siguiente
proceso:

```bash
umask 077
elsereno creds show --reveal --name shodan_api_key > /tmp/.shodan-key
SHODAN_API_KEY=$(cat /tmp/.shodan-key) my-other-tool ...
shred -u /tmp/.shodan-key
```

(O mejor: integra ese tool con elsereno's creds
directamente.)

---

## Postgres y persistencia

### ¿Necesito Postgres?

Sólo si querés:

- Persistencia de scans entre reinicios.
- Schedules recurrentes.
- Audit history de los schedules.
- Multi-usuario (planeado).

Para uso ad-hoc (`elsereno scan` por lotes), no.

### ¿Postgres 14 / 15 / 17 sirven?

El binario está validado contra Postgres 16. Versions 14/15
**probablemente** funcionan (no usa nada de 16-only en las
migraciones), pero no están en el CI matrix. Postgres 17
recién está saliendo (Q1 2026) — testing pendiente.

### ¿Puedo usar SQLite en lugar de Postgres?

No. La elección de Postgres se basa en:

- `pgx.CopyFrom` para batch insert de findings (10× más
  rápido que SQLite).
- Constraints CHECK con CASCADE/SET NULL.
- JSONB indexing.
- `serializable` isolation para concurrent updates.

SQLite carece de varios de estos. Sería un fork
significativo.

### ¿Cómo escalo Postgres para muchos findings?

- **Particionado**: `findings` por mes con `pg_partman`.
  Migration 00006 dejó hooks para esto (no obligatorio).
- **Read replicas**: streaming replication estándar.
- **`pgbouncer`** front para pooling.
- `pool_max` en config (default 16) — para 50+ workers
  necesitarás subirlo.

---

## Scans + plugins

### ¿Por qué un target no aparece en los findings?

Posibles causas en orden de probabilidad:

1. **Scope rechazo**: tu `scope.yaml` no lo incluye.
   Comprueba con `elsereno doctor` o pasa `--no-scope`
   temporalmente para confirmar.
2. **Puerto cerrado**: el TCP-connect probe falló. Verifica
   con `nc -zv host port`.
3. **Probe falló a nivel protocolo**: el target responde
   pero el handshake del plugin no cuadra. Usa
   `--verbose` para ver detalles.
4. **Capability score = 0**: el plugin SÍ lo procesó pero
   el match es nulo. Inspecciona con `elsereno fingerprint
   capture` + `validate`.

### ¿Puedo crear un plugin custom?

Sí, pero implica compilar tu fork:

1. `internal/plugins/myplugin/probe.go` implementando la
   interfaz `core.Plugin`.
2. `internal/plugins/myplugin/init.go` con `init()` que
   registra el plugin en el global registry.
3. `go build -o elsereno ./cmd/elsereno` — el plugin queda
   compilado en el binario.

No hay plugin-as-shared-library en v1.88 (intencional: el
modelo es "todo en el binario" para reproducibilidad +
single attack surface). Plugin marketplace está en vNext.

### ¿Cómo veo qué plugins se aplicaron a un target?

`elsereno scan --verbose` imprime un line per
plugin-attempted-target-port. O directamente:

```bash
elsereno plugins ports | grep 502
# → modbus  (port 502)
```

Cuando un target tiene puerto 502, sólo modbus se le
aplica. Si tiene 502 + 4840, modbus + opcua. Etc.

### ¿Es seguro escanear producción ICS con esto?

**Read-only build (default)** ha sido cuidadoso con cada
plugin para que las probes sean idempotentes y no
disruptivas:

- Modbus: `FC 17 Report Server ID` + `FC 43 Read Device ID`
  (ambos read-only).
- OPC UA: handshake HEL → ACK (sólo).
- S7: `Setup Comm` + `Read SZL` (read-only ID).
- BACnet: `Who-Is` broadcast (lectura).
- Etc.

Dicho esto: ningún plugin es 100% no disruptivo en
hardware viejo / buggy. Si auditas un PLC de 1995 sabiendo
que se cuelga ante banners "raros", **no lo escanees sin
ventana de mantenimiento**. Plugin notes en
[`docs/protocols/<name>.md`](protocols/) documentan
gotchas por dispositivo.

**Offensive build**: cualquier escritura requiere
triple-confirm + scope explícito + audit obligatorio. No
puede dispararse por accidente.

---

## Dashboard y serve

### ¿Cómo accedo al dashboard sin TLS desde otra máquina?

**No deberías** (PITF-020), pero si insistes en LAN
de confianza:

```bash
elsereno serve \
    --addr 0.0.0.0:8787 \
    --i-know-what-im-doing
    # NO --tls-cert/key → ERROR. Serve rechaza esto.
```

Serve **exige** TLS para non-loopback. Workaround: bindea
loopback en el host + SSH tunnel:

```bash
ssh -L 8787:127.0.0.1:8787 elsereno-host
# Local browser → http://127.0.0.1:8787
```

### ¿Por qué `/api/v1/scans` devuelve 503?

Porque `--scan-store=off` (default). Cámbialo:

```bash
elsereno serve --scan-store=memory   # volátil
elsereno serve --scan-store=db       # persistente, requiere DATABASE_URL
```

### El dashboard se ve raro / no carga

Causas comunes:

1. **CSP bloqueando assets**: chequea la consola del
   browser. ElSereno emite CSP estricto con nonces; si
   un add-on inyecta scripts, los bloquea.
2. **Vault locked**: el CSRF key se deriva del vault. Si
   `serve` arrancó sin unlock, /api/v1/* devuelve 503.
3. **Stale binary** — ver troubleshooting en
   [MANUAL.md §10](MANUAL.md#10-troubleshooting).

### ¿Cómo cierro `serve`?

Ctrl+C envía SIGINT → exit 130 (graceful, zeroiza vault,
flushea audit).
`kill -TERM <pid>` → exit 143 (idem).
`kill -9 <pid>` → exit forzado; el vault zeroiza por
finalizers pero `audit.jsonl` puede quedar mid-write.
**No recomendado.**

### ¿Soporta autenticación OIDC / SAML / LDAP?

No actualmente. El dashboard usa un token TTL=30d (default)
asignado al primer operador. Multi-usuario con OIDC
(Keycloak/Azure AD) + roles (viewer/analyst/admin) está
en vNext.

---

## Performance

### ¿Cuántos targets por segundo?

Depende del plugin. Benchmarks rough en desktop con
`scan-pool=8`:

- `banner`: ~200/s.
- `modbus`: ~80/s.
- `bacnet`: ~150/s (UDP, no handshake).
- `cwmp`: ~30/s (HTTP request + parse).
- `mms`: ~40/s (handshake largo).

Cuello de botella casi siempre es el target (timeout o
ICMP rate-limit). Subir `scan-pool` raramente ayuda más
allá de `nproc - 2`.

### ¿Cómo limito la velocidad para no DoSear targets frágiles?

```yaml
scan:
  max_concurrent: 4           # un puñado, no decenas
  per_target_timeout: 30s     # generoso
```

Plus `--scan-pool 2` (default). Para protocolos
particularmente frágiles (DLMS meters), agrega 1-2s
delay entre targets via wrapper script:

```bash
while read -r t; do
  echo "$t" | elsereno scan --input stdin
  sleep 2
done < targets.txt
```

### Mi DB crece sin parar

Usa retención de findings + audit:

```bash
# Audit retention (automático con --audit-retention-days):
elsereno serve --audit-retention-days 90 ...

# Findings retention: aún manual via SQL:
psql "$DATABASE_URL" -c "DELETE FROM findings WHERE ts < NOW() - INTERVAL '180 days';"
```

Findings auto-retention es item vNext.

---

## Audit + compliance

### ¿Es válido como evidencia legal?

Depende de la jurisdicción + cómo lo procesas. El audit
log:

- Es append-only con HMAC chain (tamper-evident).
- Cada entry tiene timestamp + actor + payload.
- `verify` detecta modificaciones post-hoc.

Para forensia: mantén el `audit.jsonl` + el vault file
(no la passphrase) + checksum SHA-256 firmado por GPG.
Te confirma que la chain era válida en ese instante.

### ¿Cómo exporto el audit log a mi DLP?

Ver [INTEGRATIONS.md](INTEGRATIONS.md) — patrón general
(file → forwarder → SIEM) aplica al audit igual que a
findings.

### ¿Tengo que cumplir GDPR / personal data?

ElSereno NO captura PII por default — registra IPs +
banners + device IDs. Si tu organización considera la
IP como PII (algunas autoridades de protección de datos
europeas), incluye `audit.jsonl` en tu retention policy
y configura `--audit-retention-days` acordemente.

---

## Desarrollo

### ¿Cómo levanto un entorno de desarrollo?

`scripts/bootstrap.sh` (deps) + `scripts/start.sh` (todo
arriba). Ver [`DEV-SETUP.md`](DEV-SETUP.md).

### ¿Cómo escribo un plugin nuevo?

1. Lee 2-3 plugins existentes pequeños:
   `internal/plugins/banner/`, `internal/plugins/atmodem/`.
2. Crea `internal/plugins/myplugin/` con `probe.go` +
   `init.go`.
3. Sigue la interface `core.Plugin`.
4. Añade tests con un protocol simulator si es factible
   (`simulators/<name>/`).
5. Documenta en `docs/protocols/<name>.md`.
6. `make build` + `make ci`.

Ver [`.context/protocols/_template.md`](../.context/protocols/)
para plantilla.

### ¿Cómo corro los tests?

```bash
make test           # unit
make test-race      # con race detector
make test-cover     # cobertura
make test-fuzz      # fuzzing (5 min default)
make ci             # superset de CI: lint + build × 3 variants + test-race + test-cover + sec + context-check
```

### ¿Cómo contribuyo?

1. Fork → branch → cambios.
2. `make ci` debe pasar local antes de PR.
3. Si añades verb / flag / API: actualiza
   [`MANUAL.md`](MANUAL.md) + [`INSTALL.md`](../INSTALL.md)
   si aplica.
4. PR contra `main`. CI corre con billing GitHub
   restaurado (de momento `workflow_dispatch:` only).
5. Espera review.

---

## Más

- [`MANUAL.md`](MANUAL.md) — referencia general.
- [`DEV-SETUP.md`](DEV-SETUP.md) — dev workflow.
- [`SECURITY.md`](SECURITY.md) — modelo de seguridad.
- [`INTEGRATIONS.md`](INTEGRATIONS.md) — SIEM / observ.

¿Tu pregunta no está aquí? Abre un issue marcado `question`
o `docs`.
