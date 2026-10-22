# ElSereno, FAQ expandida

Preguntas frecuentes con respuestas detalladas. Para
preguntas rápidas con un párrafo de respuesta, ver el
[§22 del MANUAL.md](MANUAL.md#22-faq-rápida).

---

## Instalación

### ¿Qué binario instalo: default, offensive o mini?

- **default** (`elsereno`): el 90% de los casos. Scan
  read-only, dashboard, TUI, 35 plugins. Lo que querés si
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
usuario sin privilegios, sólo necesita `cap_net_bind_service`
si quiere bindear puertos <1024:

```bash
sudo setcap cap_net_bind_service=+ep /usr/local/bin/elsereno
```

### ¿Es portable a Windows?

**Aún no**. Bloqueadores:

- `syscall.*` por-plataforma en `internal/audit` (file
  locking via flock, usaríamos `LockFileEx` en Windows).
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

**No hay recuperación**. El vault se cifra con una clave derivada
con Argon2id de la passphrase; sin ella, el vault es bytes random.
Sin escape-hatch a propósito (PITF-021).

Opciones:

1. Si conservas una copia antigua de `vault.v1.bin` y **conoces su
   passphrase**: ponla en `~/.elsereno/` (0600). Un `backup` de
   `elsereno backup create` no sirve para esto: se descifra con el
   vault que lo creó (MANUAL §20, PITF-093).
2. Si no: `rm ~/.elsereno/vault.v1.bin`, `vault init` con
   nueva passphrase, `creds store` re-importar cada
   credencial manualmente.

### ¿Puedo cambiar la passphrase del vault?

No: no hay verbo para cambiarla (`vault rotate` está en vNext). Un
backup no sirve de puente, porque se descifra con la misma master
del vault que lo creó. La única vía es crear un vault nuevo y volver a
guardar cada credencial:

```bash
elsereno creds list                           # con el vault viejo
elsereno creds show shodan_api_key --reveal   # una a una; anótalas fuera de la shell
mv ~/.elsereno/vault.v1.bin ~/.elsereno/vault.v1.bin.old
elsereno vault init                           # con la passphrase nueva
elsereno creds store shodan_api_key           # pide passphrase y valor sin eco
# cuando estén todas: shred -u ~/.elsereno/vault.v1.bin.old
```

Workaround feo, lo sé. PR welcome.

### ¿Por qué `creds store --plaintext '<api-key>'` no funciona?

Intencional. PITF-032: secrets en argv son visibles en
`ps -ef`. La forma correcta es dejar que lo pida sin eco, o pasarlo
por stdin:

```bash
elsereno creds store shodan_api_key           # pide passphrase y valor sin eco
# Por tubería, creds store y rotate leen DOS líneas de stdin: la
# passphrase del vault y después el valor (sin TTY no preguntan).
read -s -r PP && read -s -r KEY && printf '%s\n%s\n' "$PP" "$KEY" | elsereno creds store shodan_api_key
unset PP KEY
```

### ¿Cómo expongo una credencial a otro proceso?

`creds show shodan_api_key --reveal` imprime los metadatos y el
plaintext (línea `value:`) a stdout. El reveal **no** queda en la
cadena de auditoría todavía: solo se avisa por stderr. Pipe a un
archivo 0600 si necesitas persistirlo para un siguiente proceso:

```bash
umask 077
elsereno creds show shodan_api_key --reveal | sed -n 's/^value: *//p' > /tmp/.shodan-key
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
recién está saliendo (Q1 2026), testing pendiente.

### ¿Puedo usar SQLite en lugar de Postgres?

No. La elección de Postgres se basa en:

- `pgx.CopyFrom` para insertar findings por lotes (diseño de
  ADR-008, no construido: hoy `serve` escribe cada finding con un
  `INSERT`).
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
- `database.max_conns` en config (default 10); con muchos
  workers (`--scan-pool`) necesitarás subirlo.

---

## Scans + plugins

### ¿Por qué un target no aparece en los findings?

Posibles causas en orden de probabilidad:

1. **Scope rechazo**: pasaste `--scope` y tu `scope.yaml` no
   lo incluye (rangos o puertos). Compara el target con
   `ranges` y `ports`; el resumen `scan complete: ... (from N
   targets ...)` cuenta solo los que pasaron el filtro. No
   repitas sin `--scope` para comprobarlo: tocarías justo lo
   que el scope dejó fuera.
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
3. `go build -o elsereno ./cmd/elsereno`: el plugin queda
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
triple-confirm y queda auditada. No puede dispararse por
accidente. Con `--scope`, `write modbus send`, `exploit run` y
`proxy listen` rechazan un target fuera del scope (77) y exigen
una IP, no un nombre.

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

Serve **exige** TLS, `--i-know-what-im-doing` y OIDC
(`auth.oidc.issuer`, `audience`, `jwks_url`) para non-loopback; sin
cualquiera de los tres sale con 64 antes de escuchar. Lo mismo vale
dentro de un contenedor, donde el `127.0.0.1` por defecto es el del
contenedor: `docker run -p 8787:8787 ... serve` no llega (receta
probada en el §2.3 del MANUAL). Workaround: bindea loopback en el
host + SSH tunnel:

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
3. **Stale binary**: ver troubleshooting en
   [MANUAL.md §10](MANUAL.md#10-troubleshooting).

### ¿Cómo cierro `serve`?

Ctrl+C envía SIGINT → exit 130 (cierre ordenado del
servidor). `kill -TERM <pid>` → exit 143 (idem). Ningún
manejador de señal borra la master key: la memoria de
memguard se libera al terminar el proceso. (Hasta el
21-10-2026 un SIGINT salía también con 143.)
`kill -9 <pid>` → exit forzado; `audit.jsonl` puede quedar
a medio escribir. **No recomendado.**

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
scanner:
  max_concurrent_targets: 4   # un puñado, no decenas
  max_concurrent_per_host: 1  # nunca dos sondas a la vez a un host
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

Ver [INTEGRATIONS.md](INTEGRATIONS.md), patrón general
(file → forwarder → SIEM) aplica al audit igual que a
findings.

### ¿Tengo que cumplir GDPR / personal data?

ElSereno NO captura PII por default, registra IPs +
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
   `internal/protocols/banner/`, `internal/protocols/atmodem/`.
2. Crea `internal/protocols/myplugin/` con un `Default()` que
   devuelva el `core.Protocol` y su `Metadata()`.
3. Regístralo con `core.Register` en `cmd/elsereno/plugins.go`
   (ahí están los 35).
4. Añade tests con un protocol simulator si es factible
   (`simulators/<name>/`).
5. Documenta en `docs/protocols/<name>.md`.
6. `make build` + `make ci`.

Ver [`.context/templates/protocol.md`](../.context/templates/protocol.md)
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

- [`MANUAL.md`](MANUAL.md), referencia general.
- [`DEV-SETUP.md`](DEV-SETUP.md), dev workflow.
- [`SECURITY.md`](SECURITY.md), modelo de seguridad.
- [`INTEGRATIONS.md`](INTEGRATIONS.md), SIEM / observ.

¿Tu pregunta no está aquí? Abre un issue marcado `question`
o `docs`.
