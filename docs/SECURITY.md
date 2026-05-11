# ElSereno — security model

Resumen del modelo de seguridad para el operador de SOC,
auditor de compliance, o threat-modeller que necesita
entender qué garantiza el binario y dónde están sus límites.

> Este documento describe el modelo **vigente** (v1.88).
> Para decisiones de diseño detalladas, ver
> `.context/decisions/*.md` (ADRs); para anti-patrones
> identificados, `.context/pitfalls.md`.

---

## Índice

1. [Boundary del proceso](#1-boundary)
2. [Vault: claves + credenciales](#2-vault)
3. [Audit chain (tamper-evidence)](#3-audit-chain)
4. [TLS + bind policy](#4-tls--bind-policy)
5. [Subprocess (PITF-022): execve via SafeCommand](#5-subprocess)
6. [Secret-transport policy (PITF-032)](#6-secret-transport)
7. [Reproducible builds + supply-chain](#7-supply-chain)
8. [Write-gates (offensive build)](#8-write-gates)
9. [Scope enforcement](#9-scope-enforcement)
10. [Network reach + sandbox](#10-sandbox)
11. [Hardening checklist (prod)](#11-hardening-checklist)
12. [Reporting vulnerabilities](#12-reporting)

---

## 1. Boundary

Un proceso `elsereno` actúa sobre tres capas:

```
                ┌────────────────────────────────┐
                │      OPERATOR (interactive)    │
                │  vault passphrase (TTY/file)   │
                └────────────┬───────────────────┘
                             │
                             ▼
                ┌────────────────────────────────┐
                │      ELSERENO PROCESS          │
                │  ┌──────────┐  ┌──────────┐    │
                │  │ vault    │  │ audit    │    │
                │  │ memguard │  │ chain    │    │
                │  │ AES-GCM  │  │ HMAC     │    │
                │  └──────────┘  └──────────┘    │
                └────────────┬───────────────────┘
                             │
                             ▼
                ┌────────────────────────────────┐
                │   NETWORK (targets + DB)       │
                │   TCP probes + optional pg     │
                └────────────────────────────────┘
```

Garantías de boundary:

- **El operador es el único trust anchor**. La passphrase
  del vault no se persiste en disco salvo en un archivo
  0600 explícito (`--vault-passphrase-file`). No hay
  recuperación si se pierde.
- **Vault unlock-once**: una vez desbloqueada, la master
  key vive en memguard (mlocked, zeroed on SIGINT/SIGTERM
  + en `vault lock`). Otras invocaciones del binario
  necesitan re-unlock.
- **No hay backdoor admin**: no existe un modo "skip
  vault" o "skip audit". Vault locked → operations que
  requieren key fallan con error explícito.

---

## 2. Vault

### Diseño criptográfico

| Componente            | Algoritmo                                            |
|-----------------------|------------------------------------------------------|
| KDF passphrase → master key | scrypt (N=2^17, r=8, p=1)                        |
| Encryption envelope   | AES-256-GCM con random nonce per write              |
| Master key storage    | en memoria con `memguard` (mlocked, zeroed on signal) |
| Backup encryption     | AES-256-GCM con HKDF-derived key (`info=backup/v1`) |
| CSRF key derivation   | HKDF master key (`info=csrf/v1`)                    |
| Audit HMAC key        | HKDF master key (`info=audit/v1`)                   |

### Archivo `vault.v1.bin`

- Path por defecto: `~/.elsereno/vault.v1.bin`.
- Mode: `0600`.
- Header: magic + version + scrypt params + nonce.
- Body: AES-GCM ciphertext de un blob JSON con todas las
  credenciales.

Cambiar la passphrase **requiere desbloquear con la antigua**.
No hay rotation walk-through automatizado en v1.88 — se
hace via `backup create` → `vault init` con passphrase nueva
→ `creds store` re-importing una a una. **Item vNext.**

### Operaciones expuestas

| Verb              | Requiere unlocked? | Auditado?                       |
|-------------------|--------------------|---------------------------------|
| `vault init`     | no (crea)          | `vault_init` event              |
| `vault unlock`   | no                 | `vault_unlock` event             |
| `vault lock`     | sí                 | `vault_lock` event               |
| `vault status`   | no                 | (read-only, no audit)            |
| `creds store`    | sí                 | `creds_store` event              |
| `creds rotate`   | sí                 | `creds_rotate` event             |
| `creds show --reveal` | sí            | `creds_show_reveal` event        |
| `creds list` / `show` (no reveal) | sí | (no audit — sólo metadata)     |
| `creds purge`    | sí                 | `creds_purge` event              |

---

## 3. Audit chain

`audit.jsonl` (default `~/.elsereno/audit.jsonl`) es un
log append-only con **hash chain HMAC** que provee
**tamper-evidence**:

```
entry N:
{
  "id": "01HW...",
  "ts": "2026-05-11T12:34:56.123456Z",
  "actor": "alice@host",
  "event_type": "vault_unlock",
  "prev_hash": "<hash de entry N-1>",
  "data": {...},
  "hmac": "<HMAC-SHA256(master_key, prev_hash + body)>"
}
```

### Garantías

- **Detección de inserción**: editar / añadir entries con
  HMAC fake requiere conocer la master key → `verify-file`
  detecta.
- **Detección de borrado**: la chain se rompe → `verify`
  reporta `ErrChainBroken` con el offset.
- **Detección de reordering**: cada entry hashea el
  `prev_hash` del anterior → reordenar rompe la chain.

### Lo que **NO** garantiza

- **Disponibilidad** del archivo (rm sería detectado por
  `verify`, no impedido).
- **Read-once semantics** — un atacante con read access ve
  todo el histórico.
- **Forward-secrecy** — capturar la master key permite
  fabricar entries falsificadas hacia adelante (pero no
  retroactivas sin recomputar toda la chain).

### Tombstone purge vs compact

- `purge --before T`: borra el `data` de entries antiguas
  pero **mantiene los HMAC** → chain intacta.
- `compact --before T`: hard-delete + inserta un
  `chain_rebase` marker con el nuevo anchor. Útil para
  reducir tamaño; rompe verification de períodos previos
  al rebase (intentional).

### Daemon UDS (v1.26+)

Si varios procesos comparten el mismo audit log,
arranca:

```bash
elsereno audit serve --socket /var/run/elsereno-audit.sock
```

Cada proceso `elsereno serve` etc. envía sus eventos por
UDS al daemon, que serializa la chain. Evita races
multi-writer.

---

## 4. TLS + bind policy

### Por defecto: loopback only

`elsereno serve` bindea `127.0.0.1:8787` sin TLS y sin
asks. Single-operator, máquina personal.

### Non-loopback: triple-check

Bindear a una IP no-loopback (`10.0.0.5`, `0.0.0.0`, etc.)
**exige** tres confirmaciones:

```bash
elsereno serve \
    --addr 10.0.0.5:8787 \
    --tls-cert /etc/elsereno/server.crt \
    --tls-key  /etc/elsereno/server.key \
    --i-know-what-im-doing
```

Sin las tres flags, serve aborta con un mensaje explícito.

### TLS

- TLS 1.3 only (Go default since 1.22 con `MinVersion =
  TLS13`).
- Soporta keys RSA / ECDSA / Ed25519.
- HTTP/2 sobre h2 (ALPN).
- HSTS header agregado en non-loopback (`max-age=31536000;
  includeSubDomains`).

### Cookies

- Cookie `Secure=true` cuando TLS está activo.
- Cookie `Secure=false` con loopback HTTP, con comentario
  rationale en el código.
- `HttpOnly=true`, `SameSite=Lax`.
- Token TTL: 30 días por defecto, configurable via
  `web.token_ttl_days`.
- Token rotation bumpa `web_state.token_generation` con
  advisory lock; middleware cachea generation 5s.

### CSRF

- Key derivada por HKDF de la master key del vault
  (`info=csrf/v1`).
- Token en cookie `_csrf` + header `X-CSRF-Token` requerido
  en POST/PUT/DELETE.
- Mismatch → 403.

---

## 5. Subprocess

Cualquier `execve` interno (raro pero existe en algunos
plugins offensive) usa **`internal/exec.SafeCommand`**:

```go
exec.SafeCommand{
    Name:       "ssh",                          // binario
    Flags:      []string{"-o", "BatchMode=yes"},
    Positional: []string{user_host, "uptime"},
}
```

`SafeCommand` inyecta el separador `--` **automáticamente**
entre flags y positional. Esto previene la clase de bugs
"primer positional empieza por `-` y se interpreta como
flag" — el equivalente a SQL injection para shell.

`SafeCommand.Run()` NO usa `sh -c`. Va directo a
`syscall.Execve` (`os/exec`) con un argv array. Imposible
inyectar metacaracteres shell.

---

## 6. Secret-transport policy

ElSereno asume que un atacante con acceso al host puede
leer:

- `/proc/<pid>/environ` (env vars del proceso).
- `ps -e` output (argv).
- Logs del shell (`~/.zsh_history`, `~/.bash_history`).

Por tanto:

| ❌ Evita | ✅ Usa |
|---|---|
| `ELSERENO_VAULT_PASSPHRASE=...` env (long-lived) | `--vault-passphrase-file ~/.elsereno/dev.pp` (0600) |
| `./elsereno creds store --plaintext '<api-key>'` | `echo $KEY \| ./elsereno creds store` (stdin) |
| `curl -d "key=$API_KEY" ...` | `curl --header "@/path/to/0600.header" ...` |
| `goreleaser ... GITHUB_TOKEN=$(...)` repetido | `set` shell + leer de file |

Excepciones documentadas (cuando la env var es la forma
canónica):

- CI / cron environments donde no hay TTY ni archivo
  persistente → env acceptable con rationale en docs.
- `OTEL_EXPORTER_OTLP_ENDPOINT` (no es secret).
- `GITHUB_TOKEN` para CI runs de goreleaser (Actions inyecta
  por job).

### PITF-032 enforce

Si lanzas `serve` con `ELSERENO_VAULT_PASSPHRASE` set
**y** stdin es TTY → warning a stderr al arrancar:

```
WARN: ELSERENO_VAULT_PASSPHRASE detected in environment.
      Long-lived secrets leak via /proc/<pid>/environ + `ps e`.
      Prefer --vault-passphrase-file (0600). See PITF-032.
```

(En CI/cron sin TTY el warning no aparece — esos
contextos son los aceptables.)

---

## 7. Supply-chain

### Tags GPG signed

Todas las release tags están firmadas con
`ACE3B86BACACE7D6` (mantenedor). Verificación:

```bash
git tag -v v1.88.0
# Salida esperada:
#   gpg: Good signature from "Daniel Solís Agea <daniel.solis@zynap.com>"
```

### Reproducible builds

`make build` produce binarios deterministas:

- `-trimpath` (sin paths absolutos).
- `-ldflags="-s -w"` (sin debug info, sin DWARF).
- `-buildvcs=false` (sin commit hash incrustado salvo
  `version.Build`).
- `CGO_ENABLED=0` (pure stdlib, no glibc linking).

Dos máquinas con el mismo source tree producen el mismo
checksum del binario.

### SBOMs

Cada release incluye un SBOM CycloneDX JSON por binario:

```bash
# Vendrá en el release de GitHub:
elsereno_1.88.0_linux_amd64.tar.gz.cyclonedx.json
```

Incluye lista de módulos Go + versiones + licencias.

### Cosign keyless (opcional)

CI con GitHub Actions firmado con cosign keyless (OIDC →
Fulcio). Verificable con:

```bash
cosign verify-blob \
    --bundle checksums.txt.bundle \
    --certificate-identity-regexp 'https://github.com/RobinR00T/elSereno/.*' \
    --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
    checksums.txt
```

Cuando se ejecuta goreleaser localmente (`--skip=sign`),
el bundle no se genera. Los tags GPG-signed siguen siendo
el ground truth.

### SLSA Level 3

GitHub Actions emite attestations SLSA v1.0 via
`actions/attest-build-provenance`:

```bash
gh attestation verify dist/elsereno_1.88.0_linux_amd64.tar.gz \
    --repo RobinR00T/elSereno
```

---

## 8. Write-gates (offensive build)

El binario `elsereno-offensive` añade superficies
**activas** (writes, exploits, harvest, dial/SMS) sobre el
binario default. **Cada acción requiere triple-confirm**:

1. `--accept-writes` (flag explícito).
2. `--confirm-target <ip>:<port>` (echo del target).
3. `--confirm-token <STRING>` (token mostrado al inicio
   para confirmar que la sesión es la correcta).
4. Vault unlocked (audit HMAC se firma con la master).

### Scope por protocolo

Cada protocol gate scopea writes:

- **Modbus**: per-(area, db, byte-address) → only matching
  FCs/regs son forwardeados, resto rechazados con audit.
- **OPC UA**: per-NodeId + per-CallMethod argument types.
- **BACnet**: per-object + per-WriteProperty per-instance.
- **CWMP**: per-parameter-path + per-firmware-URL.
- **SIP / IAX2 / PBX HTTP**: per-From-domain + per-RPC.
- **CoDeSys / S7 / DLMS / etc**: TBD por protocolo.

### Audit obligatorio

Cada escritura ofensiva produce:

- `offensive_write` event con todos los parámetros + hash
  del payload.
- `scope_applied` event con match del allowlist.

`elsereno audit verify-file` debe completar exit-0 después.
Si reportas a un blue-team el archivo `audit.jsonl` es la
evidencia oficial.

### Dial / SMS

Sólo en offensive build + `--dial-allowed`. Números ≤3
dígitos están **bloqueados duro** en el binario (evita
911, 112, etc.). Wardialing batch es vNext.

---

## 9. Scope enforcement

`scope.yaml` se evalúa **antes** de tocar un target:

1. Si el target matchea `deny` → `denied: explicit deny`.
2. Si el target matchea `allow` → `allowed`.
3. Default-deny si scope está cargado y no hay match.
4. Sin scope cargado, todos los targets pasan
   (intencional para uso ad-hoc).

Findings de targets fuera de scope **NO** se emiten — el
finding tiene `scope_state: denied` y no aparece en
findings.ndjson (los logs sí registran el rechazo).

Para uso en pen-test autorizado: **scope obligatorio**.
Un `scope.yaml` en CWD se auto-carga; pasarlo explícito
es la forma robusta.

---

## 10. Sandbox

### Linux: seccomp filter (v1.26+, planeado completo)

Build offensive permite un perfil seccomp BPF que niega:

- `ptrace`, `process_vm_*` (anti-debug).
- `clone3` con flags raros.
- syscalls de raw socket / packet sockets (salvo en flujos
  raw-packet explícitos para PROFINET L2 — vNext).

### macOS: sandbox_init(3) (v1.50+)

Build `elsereno-offensive-darwin-sandboxed` (CGO):

- `make build-offensive-darwin-sandboxed`.
- Aplica un perfil sandbox_init con `(allow file-read-* …)
  (deny file-write*)` sobre paths fuera de cwd.
- Default release queda pure-Go.

### Capabilities en Linux

```bash
# Recomendado para serve no-root:
sudo setcap cap_net_bind_service=+ep /usr/local/bin/elsereno
# Permite bind <1024 sin uid=0.
```

Para discover con raw socket (raw-packet scan, vNext)
necesitaría `CAP_NET_RAW`. Default no requiere ningún
cap.

---

## 11. Hardening checklist

Para deployments productivos:

### Sistema operativo

- [ ] Usuario dedicado `elsereno:elsereno` con
      `/usr/sbin/nologin` shell.
- [ ] `/etc/elsereno/`, `/var/lib/elsereno/`,
      `/var/log/elsereno/` con perms `0750`.
- [ ] `vault.v1.bin` mode `0600` owner `elsereno`.
- [ ] `vault.pp` mode `0600` owner `elsereno` (si lo usas).
- [ ] systemd unit con hardening (ver
      [MANUAL.md §18](MANUAL.md#18-deployment)).
- [ ] AppArmor / SELinux profile aplicado (no obligatorio,
      pero recomendado).

### Red

- [ ] `serve` bindea localhost + reverse proxy con TLS al
      front, **o** TLS directo con `--tls-cert`.
- [ ] Firewall reglas restringen acceso al puerto del
      dashboard a IPs de SOC.
- [ ] Postgres en private network o socket UDS.
- [ ] Postgres TLS habilitado (`sslmode=require` o
      `verify-full`) cuando no es loopback. `database.tls_required: true`
      en config lo enforce.

### Aplicación

- [ ] `audit-retention-days` configurado (default off
      hace crecer la tabla).
- [ ] `scan-pool` ajustado al tamaño de tu fleet.
- [ ] Vault passphrase guardada en password manager + 2FA.
- [ ] Backup automático diario con retención 30 días
      mínimo.
- [ ] Restore drill cada trimestre.

### Auditoría

- [ ] `audit verify-file` corre nightly desde cron.
- [ ] Alert si exit-code ≠ 0.
- [ ] Audit log mirroreado a SIEM via
      [INTEGRATIONS.md](INTEGRATIONS.md).

### Operacional

- [ ] `legal` displayer / disclaimer revisado por
      legal/compliance.
- [ ] `scope.yaml` per-engagement con ticket SOC + ventana
      de tiempo + autorizador explícitos.
- [ ] Offensive build NO instalado en hosts de scan
      diario; sólo en jump-hosts dedicados a pen-test.
- [ ] Operators con MFA + audit log de quien hace qué.

---

## 12. Reporting

### Privately-disclosed vulnerabilities

Email: ver `SECURITY.md` en root del repo (si existe).
Alternativa: GitHub Security Advisory (private) en
`https://github.com/RobinR00T/elSereno/security/advisories/new`.

Por favor:

- **NO** abras un issue público.
- Incluye un PoC reproducible.
- Concede ~90 días para fix antes de disclosure pública.

### Lo que califica como vulnerabilidad

- Auth bypass / privilege escalation.
- Vault key extraction sin passphrase.
- Audit chain forgery.
- Memory leaks de credenciales.
- Path traversal / arbitrary file write.
- TOCTOU en operaciones de archivo.
- Issues de PITF-032 (secret leak).

### Lo que NO

- Default-deny no aplicable a target fuera de scope (es
  intencional sin scope).
- Operador con root del host puede leer
  `vault.v1.bin` + observar la passphrase via debugging
  (modelo asume operator-as-trust-anchor).
- Race conditions en `make test-race` que sólo afectan a
  tests (PRs welcome).

---

## Más documentación

- [`MANUAL.md`](MANUAL.md) — referencia general del binario.
- [`INSTALL.md`](../INSTALL.md) — instalación detallada.
- [`INTEGRATIONS.md`](INTEGRATIONS.md) — recetas SIEM/observ.
- `.context/decisions/*.md` — ADRs (Architecture Decision
  Records).
- `.context/pitfalls.md` — catálogo de anti-patrones.
- `.context/threat-model/` — threat-model documents.
