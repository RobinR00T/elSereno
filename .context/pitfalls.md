---
phase: any
status: living-catalogue
last-updated: 2026-04-19
token-budget: 5500
---

# Anti-patterns and pitfalls

Catálogo vivo. **Lectura obligatoria antes de cualquier cambio de código o config.**

Al detectar nuevo anti-patrón: añadir entrada con el formato de `templates/pitfall.md` (H2 + prosa).

---

## PITF-001 — Counter de sesión no persistido
**Síntoma**: revocación falla tras restart; cookies viejas reviven.
**Regla**: counters de invalidación persisten (BD o fichero).
**Implementación correcta**: tabla `web_state(key, token_generation)`; `UPDATE ... RETURNING` con advisory lock.
**Ver**: ADR-014.

## PITF-002 — Ciclo de dependencias en derivación de claves
**Síntoma**: "deriva X del vault; si no hay vault, crea X y cifra con passphrase del vault" — sin vault no hay passphrase.
**Regla**: clave dependiente del vault exige vault inicializado; si falta, error claro (no auto-crear).
**Ver**: ADR-017.

## PITF-003 — Exit code único para todas las señales
**Síntoma**: SIGINT y SIGTERM devuelven el mismo código.
**Regla**: convención Unix `128 + signum`. SIGINT=130, SIGTERM=143. Segunda señal durante drain → exit inmediato mismo código.

## PITF-004 — Redaction con patrones demasiado amplios
**Síntoma**: logs legítimos machacados (`sort_key`, UUIDs).
**Regla**: patrones específicos + heurística de entropía con pre-filter de UUIDs v1-v5.
**Patrones válidos**: `api_key, secret_key, private_key, access_key, session_key, encryption_key, auth_token, refresh_token, bearer_token, password, passphrase, secret, authorization, cookie`.

## PITF-005 — Prompt de passphrase en batch
**Síntoma**: scan 1000 targets pide passphrase 1000 veces.
**Regla**: vault unlock-once; master key cacheada en memguard; zeroizada al shutdown o `vault lock`.
**Ver**: ADR-018.

## PITF-006 — CGO cross-compile sin toolchains
**Síntoma**: goreleaser con CGO=1 falla cross-compilando.
**Regla**: CGO no cross-compila sin toolchains; variantes CGO solo nativo del runner.

## PITF-007 — Referencia rota a versión anterior
**Síntoma**: "ver sección X del v5" — lector no tiene v5.
**Regla**: documentos entregables autosuficientes; todo contenido referenciado inline.
**Detector**: `context-check.sh` hace grep de patrones `(versión anterior|del v[0-9]+|mantener del v[0-9]+|sección v[0-9]+ sin cambios)`.

## PITF-008 — Asumir comportamiento CLI externo
**Síntoma**: documentar flujo con CLI que no se comporta como dices.
**Regla**: verificar comportamiento real; si duda, alternativa directa (escritura fichero).

## PITF-009 — Error tipado mal ubicado
**Síntoma**: errors del paquete X declarados en paquete Y.
**Regla**: sentinels en paquete emisor; `core/errors.go` solo para dominio compartido.

## PITF-010 — Config ejemplo desalineada con entorno dev
**Síntoma**: `.env.example` sin password + docker-compose con password → copia directa no conecta.
**Regla**: coherencia `.env.example` ↔ servicios dev; si DSN sin password, servicio con trust auth loopback.

## PITF-011 — Dependencia legacy sin verificar estado
**Síntoma**: se referencia lib archivada.
**Regla**: verificar estado de mantenimiento al introducir dep; si archivada, documentar alternativa + PITF.
**Casos**: `google/gopacket` → `gopacket/gopacket`. `mattn/go-sqlcipher` → `mutecomm/go-sqlcipher/v4`. `elastic/go-seccomp-bpf` → verificar en F5.

## PITF-012 — Generador no cubre todas las secciones
**Síntoma**: asumir `cobra/doc` genera man1/5/7; solo man1.
**Regla**: man5 y man7 manuales (pandoc); script `gen-manpages.sh` invoca ambas rutas desde `man/src/man{5,7}/*.md`.

## PITF-013 — Contenido vacío inválido para generador
**Síntoma**: "vacío F0" → pandoc rechaza.
**Regla**: todo artifact generable tiene contenido mínimo válido.

## PITF-014 — Campos JCS no enumerados
**Síntoma**: hash chain JCS sin lista exacta de campos → hashes divergentes.
**Regla**: enumerar campos exactos; excluir derivados.
**Campos audit_log**: `id, occurred_at, actor, event_type, payload, prev_hash`.

## PITF-015 — Comando destructivo sin modo batch
**Síntoma**: solo prompt interactivo → no CI/cron.
**Regla**: destructivos con dos modos — interactivo (`YES`) y batch (`--yes` + flag de riesgo `--i-break-the-chain`).

## PITF-016 — Secretos via argv o herestring
**Síntoma**: API key queda en shell history y `ps`/`proc/<pid>/cmdline`.
**Regla**: nunca secretos en argv ni herestring; `read -rs` + redirección a fichero + `unset`.
**Implementación correcta**:
```bash
read -rs KEY
printf '%s' "$KEY" > ~/.shodan/api_key
chmod 600 ~/.shodan/api_key
unset KEY
```

## PITF-017 — Documento auto-contradictorio
**Síntoma**: regla en sección A violada en sección B del mismo documento.
**Regla**: tras cada edición importante, cross-check reglas contra implementación descrita; resolver o documentar excepción con rationale.

## PITF-018 — Referencia a fichero/directorio ausente de la estructura
**Síntoma**: script lee `man/src/` pero la estructura del repo no lo incluye → fallo primera ejecución.
**Regla**: cada path referenciado existe en el árbol; añadir al árbol si se introduce.

## PITF-019 — Template incoherente con uso real
**Síntoma**: template formato A; uso real formato B.
**Regla**: template refleja exactamente el formato del uso real.

## PITF-020 — Servicio con defaults permisivos sin bind explícito
**Síntoma**: `docker-compose` trust auth publica en `0.0.0.0` → LAN conecta sin password.
**Regla**: servicios con defaults permisivos requieren bind explícito loopback (`127.0.0.1:port:port`).

## PITF-021 — Comando que auto-crea estado crítico silenciosamente
**Síntoma**: `serve` auto-inicializa vault → typo passphrase crea vault vacío.
**Regla**: inicialización crítica exige comando explícito (`vault init`); operativos fallan con mensaje claro si estado previo falta.

## PITF-022 — Enum-like sin valores enumerados
**Síntoma**: campo config `tls_required=auto` sin definir valores permitidos.
**Regla**: enum-like con enumeración explícita + semántica; validar en parse.
**Casos**: `database.tls_required` ∈ {auto, always, disable}; `audit_log.event_type` CHECK constraint.

## PITF-023 — Subprocess con flag injection posible
**Síntoma**: target controlado por input empieza por `-` → subprocess lo interpreta como flag.
**Regla**: separador `--` determinista entre flags y posicionales; `SafeCommand(CommandSpec{Name, Flags, Positional})` lo aplica.
**Ver**: ADR-024.

## PITF-024 — Precisión de timestamp inconsistente con storage
**Síntoma**: spec dice "Nano" pero Postgres `TIMESTAMPTZ` es microsegundos → trunca silenciosamente.
**Regla**: alinear precisión código/serialización/storage. Spec dice "RFC3339 con hasta 6 dígitos fracción" (ADR-020).

## PITF-025 — Operaciones caras en health checks
**Síntoma**: `/readyz` verifica cadena completa audit → tarda minutos → probe falla → reinicio.
**Regla**: health checks baratos; integridad con muestra limitada controlada por config.
**Casos**: `readyz.audit_tail_entries=100`.

## PITF-026 — Race en bump de counter
**Síntoma**: dos operadores rotan counter simultáneamente → inconsistente.
**Regla**: counters críticos en transacción con advisory lock.
**Implementación correcta**:
```sql
BEGIN;
SELECT pg_advisory_xact_lock(hashtext('web_state_token_rotate'));
UPDATE web_state SET token_generation = token_generation + 1, updated_at = NOW()
  WHERE key='default'
  RETURNING token_generation;
COMMIT;
```

## PITF-027 — Reintentos sin límite ni dead-letter
**Síntoma**: `outbox` reintenta para siempre.
**Regla**: `max_attempts` acotado; al agotar, mover a tabla `_dead` con `last_error`.

## PITF-028 — Operación reversible sin comando de reversión
**Síntoma**: `vault unlock` sin `vault lock` → reiniciar proceso.
**Regla**: operación reversible sobre estado en memoria tiene comando explícito de reversión (`lock`, `logout`, `stop`).

## PITF-029 — Meta-contradicción de reglas
**Síntoma**: el documento aplica una regla en una sección y la viola en otra.
**Regla**: tras cada edición del documento, grep de patrones prohibidos contra el propio documento.
**Detector**:
```bash
grep -nE '(versión anterior|del v[0-9]+|mantener del v[0-9]+)' elsereno-prompt.md && echo VIOLATES || echo ok
```

## PITF-030 — Duplicación desincronizada
**Síntoma**: misma enumeración en dos sitios (p. ej. header changelog + SQL CHECK); al editar uno se olvida el otro.
**Regla**: un solo source of truth por enumeración; el resto son derivados marcados como tal.
**Casos**: audit `event_type` SoT = SQL DDL; redaction patterns SoT = `conventions.md`.

## PITF-031 — Make ci drift respecto al CI remoto
**Síntoma**: `make ci` local omite jobs que el CI remoto sí corre (builds -tags offensive, fuzz, go-licenses) → bitrot no detectado hasta el push.
**Regla**: `make ci` es superset funcional de los jobs del CI que detectan bitrot (todas las variantes de build + tests + seguridad completa).
**Implementación correcta**: target `ci: lint build build-offensive test-race test-cover test-fuzz sec context-check`. `make sec` incluye `go-licenses check` además de gosec/govulncheck/trivy/gitleaks. Documentar en CONTRIBUTING que `make ci` es aproximación local (el remoto es autoritativo) y aun así cubre el mismo espacio. El variant `-tags sqlite` fue retirado en v1.2.

## PITF-032 — Env vars con secretos
**Síntoma**: secretos en env (`ELSERENO_VAULT_PASSPHRASE`, API keys) leakean via `/proc/<pid>/environ` y `ps e`.
**Regla**: secretos persistentes en fichero con 0600 o vault cifrado; env acceptable para CI/cron pero con warning al arrancar si hay TTY (indica que probablemente es uso interactivo por error). Nunca en argv ni herestring.
**Implementación correcta**: en `creds` module, detect `isatty(stderr)` + env var con secreto → imprimir warning recomendando `vault unlock` interactivo o fichero 0600.
**Ver**: ADR-026.

## PITF-033 — FK sin ON DELETE action contra entidad hard-deletable
**Síntoma**: tabla A.x referencia B.id sin `ON DELETE`; otro comando hace hard-delete en B → FK violation o row huérfana.
**Regla**: declarar `ON DELETE` action explícito (`CASCADE`, `SET NULL`, `RESTRICT`) y/o una regla dura que impida el hard-delete de la entidad referenciada. Documentar la interacción en el ADR relevante.
**Casos**: `audit_purge_markers.audit_entry_id` → `audit_log(id) ON DELETE RESTRICT` + regla ADR-013 que excluye `event_type IN ('genesis','chain_rebase','purge_event')` del `audit compact`.

## PITF-034 — Lectura per-request de estado persistido sin cache
**Síntoma**: middleware web consulta `web_state` en cada request para validar `token_generation` → DB round trip lineal con QPS → saturación pool/latencia.
**Regla**: estados que cambian raramente pero se leen en caliente van detrás de cache con TTL corto (o invalidación por event bus). Aceptar ventana stale acotada.
**Implementación correcta**: `web.token_generation_cache_ttl=5s`. Rotación invalida cookies en ≤TTL segundos — tolerable para caso de uso.

## PITF-035 — Tags de imágenes Docker flotantes
**Síntoma**: `image: postgres:16` o `image: adminer` sin tag. Docker Hub mueve la etiqueta; en la siguiente reconstrucción aparece una versión distinta y las migraciones/feature flags divergen silenciosamente entre máquinas o entre CI y local.
**Regla**: pin exacto en la etiqueta (`postgres:16.3-alpine3.20`, `adminer:4.8.1`) y preferible también pinear el digest `@sha256:…` en contextos prod. Actualizar tag es cambio explícito con PR, no deriva.
**Implementación correcta**: `docker-compose.dev.yml` usa tags exactos; `Dockerfile` builder stage también pinneado (`golang:1.23.4-alpine3.20`). Esto es variante contenedor de PITF-011.

## PITF-036 — Detector auto-referencial
**Síntoma**: un script lint/detector contiene como string los patrones que busca. Al ejecutarlo sobre el árbol completo, se detecta a sí mismo (o a la documentación que los define, como `pitfalls.md`) y siempre falla.
**Regla**: detectores que buscan patrones textuales excluyen los ficheros donde los patrones se definen (típicamente `pitfalls.md` y el propio script) **y** ignoran bloques de código (fences triple-backtick).
**Implementación correcta**: awk que alterna un flag `in_code` al ver `^```` y solo matchea fuera; `find` con `! -name pitfalls.md`. Verificado contra el propio catálogo antes de comitear.

## PITF-037 — Enviar a un canal que otra goroutine puede cerrar
**Síntoma**: `panic: send on closed channel` intermitente bajo carga. Un fan-out toma un snapshot de subscribers, suelta el lock y envía fuera de él, mientras un `cancel` cierra ese canal. Si el pánico ocurre en una goroutine sin `recover` (worker, scheduler, observer), cae el proceso entero.
**Regla**: nunca cerrar un canal que puede tener varios emisores sin sincronización. O bien (a) el envío y el `close` son mutuamente exclusivos bajo el mismo `RWMutex` (envío bajo `RLock` con `select ... default` no bloqueante; `close` bajo `Lock`), o bien (b) no se cierra nunca el canal de datos y se señaliza el fin con un `done chan struct{}` cerrado una sola vez (`sync.Once`), que los emisores observan con `select { case ch <- v: case <-done: default: }`.
**Ver**: broadcaster SSE, commit c441eb4.

## PITF-038 — Leer estado compartido tras un `Handle` que no hace join
**Síntoma**: un `Handle` lanza goroutines y retorna al primer error o a `ctx.Done()` sin esperar a que todas terminen; un llamador lee después un contador/veredicto que una goroutine superviviente sigue mutando. Data race (lo caza `go test -race`) y lectura sobre estado parcial.
**Regla**: el estado compartido entre la goroutine de trabajo y el lector se protege con mutex/atómicos, o el `Handle` hace join (`WaitGroup` / drenar todas las entradas del canal de errores) antes de exponer el resultado. Un comentario que dice "leer solo tras terminar" no es sincronización.
**Ver**: gatedproxy ENIP `obs`, commit c441eb4.

## PITF-039 — Familia de función que "straddlea" read/write sin gate por subcódigo
**Síntoma**: una matriz allow/deny clasifica una familia entera (Modbus FC8 Diagnostics, MEI, un servicio CIP contenedor) como una sola categoría y la reenvía o bloquea en bloque. Dentro hay subcódigos que mutan estado (Force Listen Only, Restart, Clear Counters), así que el write-ban por defecto deja pasar un DoS al equipo pese a prometer read-only.
**Regla**: toda familia cuyos subcódigos crucen la frontera read/write se clasifica **por subcódigo**, no por familia. Por defecto (read-only) solo pasan los subcódigos de lectura pura; un frame corto/malformado se bloquea (fail-closed). En build ofensivo la subfamília peligrosa exige estar en el allowlist con su subcódigo.
**Ver**: Modbus FC8, commit c6bdf38.

## PITF-040 — Paginar por el recuento filtrado en vez del crudo
**Síntoma**: un paginador para cuando una página devuelve menos elementos de los pedidos, pero el recuento se toma **después** de filtrar filas inválidas (IP/puerto no parseables, IPv6 no soportado). Una página con unas pocas filas descartadas parece "fin del dataset" y se truncan en silencio las páginas siguientes.
**Regla**: la condición de terminación de la paginación se decide con el recuento **crudo** de la respuesta (`len(parsed.Matches)`), nunca con el recuento tras filtrar. Devolver ambos si hace falta.
**Ver**: Shodan/FOFA `SearchPaged`, commit c6bdf38.

## PITF-041 — `io.ReadAll` sin límite en la ruta no confiable
**Síntoma**: un proxy/handler bufferiza un cuerpo con `io.ReadAll(req.Body)` para inspeccionarlo. Un POST gigante o un stream chunked que no termina agota la memoria del proceso (DoS), justo en el componente inline que se sitúa delante del equipo protegido.
**Regla**: acotar toda lectura de datos no confiables con `io.LimitReader(r, max+1)` (o `http.MaxBytesReader`) y **rechazar** lo que exceda, no truncar y reenviar (un cuerpo truncado corrompe la request aguas arriba). El tope se comparte con el de los proxies hermanos (p. ej. 1 MiB).
**Ver**: proxy CWMP, commit c6bdf38.

## PITF-042 — Parser de detección ciego al formato dominante real
**Síntoma**: un clasificador/scorer solo reconoce una codificación minoritaria de un campo (segmentos lógicos de clase) y rechaza la que usa el tráfico real más común (segmento simbólico ANSI `0x91` con nombre de tag en Logix). La regla anti-falso-positivo produce entonces el falso negativo que pretendía evitar: el veredicto queda "limpio/ciego" ante escrituras reales.
**Regla**: un parser cuyo propósito es detección debe cubrir los formatos que el objetivo usa de verdad, no solo el del spec-book. Verificar contra el tráfico dominante del vendor. Para el gate (fail-closed) rechazar lo no clasificado está bien; para la detección/scoring, no reconocerlo es un fallo de cobertura.
**Ver**: EPATH segmento simbólico `0x91`, commit c441eb4.

## PITF-043 — Gate de rango que solo valida la dirección de inicio
**Síntoma**: una allowlist por rango comprueba solo la dirección de arranque de una escritura múltiple e ignora la cantidad. Una escritura que empieza en el borde superior del rango autorizado se sale por arriba (`start ∈ [lo,hi]` pero `start+qty-1 > hi`).
**Regla**: para operaciones de rango (write multiple, read-write) validar **ambos** extremos, `start` y `start+qty-1`, y rechazar un rango que desborde el espacio de direcciones (calcular en un entero más ancho para detectar el wrap).
**Ver**: gate Modbus por rango, commit c6bdf38.

## PITF-044 — Auth fail-open en bind de red
**Síntoma**: un servidor exige TLS y un flag explícito para escuchar en una dirección no-loopback, pero **no** exige autenticación real; en modo DEV la identidad del operador se toma de una cabecera falsificable (`X-Operator`). La API queda expuesta a la red sin auth, solo con un aviso por stderr.
**Regla**: exponer una API a la red (bind no-loopback) exige autenticación real habilitada (OIDC), además de TLS. Sin ella, rechazar el arranque. La identidad DEV por cabecera solo vale en loopback.
**Ver**: `serve` `validateBindSecurity`, commit 64898cb.

## PITF-045 — Constante de protocolo incorrecta y desalineación de parser
**Síntoma**: un id/tipo de campo mal transcrito (CPF Connected Data Item como `0x00A2` cuando el estándar es `0x00B1`) hace que una rama sea código muerto y otra nunca se reconozca; además el item conectado prefija bytes (sequence count) que el parser no salta, dejándolo desalineado respecto a lo que el dispositivo ejecuta. Efecto colateral: differential de parser (el gate ve una ruta, el equipo otra) y allowlist que nunca admite el caso conectado.
**Regla**: las constantes de protocolo se cotejan contra la fuente normativa (ODVA CIP Vol 2, etc.), no contra la memoria; los prefijos por-variante (sequence count, padding) se saltan explícitamente antes de parsear el cuerpo. Un test cubre la variante conectada además de la no conectada.
**Ver**: CPF `0x00B1`, commit c441eb4.

## PITF-046 — Extraer un archivo sin guard de path traversal
**Síntoma**: al restaurar un backup/tar se hace `join(destDir, member.Name)` sin validar `member.Name`; un `../` escribe fuera del directorio destino. Que el archivo esté cifrado/autenticado mitiga (solo un insider con la clave lo explota) pero no exime.
**Regla**: todo nombre de miembro de un archivo se valida antes de escribir: `filepath.Join` + comprobar que el resultado sigue bajo el directorio destino limpio (`dst == dir || strings.HasPrefix(dst, dir+sep)`); rechazar lo que se salga. Defensa en profundidad barata.
**Ver**: restore de backup, commit 64898cb.

## PITF-047 — Componer dos programas BPF/cBPF terminales concatenándolos
**Síntoma**: se construye un filtro seccomp uniendo un sub-programa de arg-filter (que ya acaba en `RET ALLOW` + `RET ERRNO`) delante del programa de denylist de syscalls. Como seccomp evalúa UN único programa lineal y para en el primer `RET`, cualquier syscall que no case con el arg-filter cae al `RET ALLOW` intermedio y retorna ALLOW: toda la denylist de syscalls que va detrás queda como código muerto e inalcanzable. Agravado por un off-by-one en los saltos de "deny" (aterrizan en `RET ALLOW` en vez de `RET ERRNO`). El resultado da falsa garantía de aislamiento (`Available=true, kind=seccomp-bpf`) sin bloquear nada.
**Regla**: un filtro cBPF es un solo programa con UNA cola compartida. No concatenar dos programas cada uno con su `RET`. Construir un único programa (arch-check primero, denylist, luego bloques de arg-rules) y calcular CADA salto desde el índice absoluto de la instrucción al índice absoluto del `RET ERRNO` final (`offset = destino - origen - 1`), nunca con "distancias" relativas propensas al off-by-one. Los caminos "deny" saltan al `RET ERRNO`; los "allow" caen por fall-through al `RET ALLOW`.
**Verificación obligatoria**: un test que EJECUTE el programa compilado (intérprete cBPF o instalación real del filtro) y afirme el veredicto `SECCOMP_RET_*` por caso: la denylist deniega (no basta que exista), el arg-rule deniega el valor malo y permite el bueno, arch incorrecta mata. Un test que solo comprueba longitud y campo `K` NO detecta ni la denylist muerta ni el off-by-one de `Jt`/`Jf`. Y el código de test debe ejecutarse en CI: si el job de tests corre `go test ./...` sin el build-tag que compila esos ficheros (p. ej. `-tags offensive`), el test existe pero nunca corre y el bug pasa igual.
**Ver**: `offensive/sandbox/bpf_argfilter_linux.go` (`compileCombinedFilter`), re-auditoría 29-8-2026.

## PITF-048 — Llamar "tamper-proof" a un hash chain sin clave
**Síntoma**: una cadena de auditoría calcula `entry_hash = SHA-256(canonical(entry))` y se documenta como a prueba de manipulación. No lo es: cualquiera con acceso de escritura al log edita una entrada y **recomputa toda la cadena hacia delante** (los hashes son públicos), y `Verify` pasa. Es tamper-EVIDENT (detecta ediciones accidentales), no tamper-PROOF.
**Regla**: para tamper-proof, la entrada se firma con una clave que el atacante no tiene: `entry_hash = HMAC-SHA256(clave_derivada_del_vault, canonical(entry))`. Si el log se escribe desde contextos heterogéneos (unos con la clave, otros sin ella: p. ej. operaciones de escritura con vault vs. harvest de solo lectura sin vault), NO fuerces a todos a tener la clave ni partas el fichero: usa HMAC donde puedas y SHA-256 donde no, en la misma cadena. El `prev_hash` las ata: cada entrada firmada cubre el `prev_hash` (= hash de la anterior), así que manipular CUALQUIER entrada anterior rompe el `prev_hash` de la siguiente entrada firmada, que el atacante no puede recomputar. La cadena queda tamper-proof hasta la última entrada firmada. La verificación "prueba HMAC o SHA-256" no habilita downgrade por esa misma razón (la siguiente entrada firmada lo caza). Deriva la clave con dominio propio (`Vault.Derive("elsereno/audit/hmac/v1", …)`).
**Ver**: `internal/audit/canonical.go` (`computeHash`/`verifyEntry`), re-auditoría 30-8-2026.

## PITF-049 — Escritor con estado cacheado sin lock inter-proceso cuando un hermano sí lo tiene
**Síntoma**: dos implementaciones del mismo escritor serializado (p. ej. `FileWriter` con `flock` y `DBWriter` con solo un mutex de struct). El que solo tiene mutex cachea el estado de encadenamiento (`prevHash`) y lo lee una vez; dos procesos leen el mismo último hash y encadenan desde él, **bifurcando la cadena**. El código ya conocía la primitiva correcta (advisory locks de Postgres usados en otra parte) pero este escritor no la usaba.
**Regla**: si un invariante exige serializar lecturas-luego-escrituras entre procesos, TODAS las rutas de persistencia necesitan el equivalente. Para Postgres con pool: una transacción con `pg_advisory_xact_lock(key)` y **re-leer el estado más reciente DENTRO del lock** en cada operación (no confiar en la caché sembrada una vez). Type-assert el conn a una interfaz `BeginTx` opcional para que producción (pool) tome el lock y los fakes de test caigan a la ruta sin lock.
**Ver**: `internal/audit/dbwriter.go` (`appendLocked`), re-auditoría 30-8-2026.

## PITF-050 — Acotar la entrada en un transporte y olvidarlo en el hermano
**Síntoma**: un parser de red pone un tope de bytes en la ruta UDP (p. ej. `make([]byte, 4096)` + un `Read`) pero pasa el `net.Conn` crudo al parser en la ruta TCP. Sobre TCP, `bufio.ReadString`/`textproto.ReadMIMEHeader` crecen la asignación con lo que el peer envíe hasta un `\n`/línea en blanco, acotados solo por el deadline de I/O: un host que transmite una línea de estado o un bloque de cabeceras interminable amplifica memoria/GC, repetible en un barrido. El tope de UDP oculta que TCP no tiene ninguno.
**Regla**: cuando el mismo parser sirve varios transportes, la cota de entrada va en TODOS. Para streams (TCP), envuelve la conexión con `io.LimitReader(conn, N)` antes de parsear, con N generoso pero finito (mayor que cualquier mensaje legítimo). No confíes solo en el deadline como límite de tamaño: acota bytes Y tiempo.
**Ver**: `internal/protocols/sip/sip.go` (`maxTCPResponseBytes`), re-auditoría 30-8-2026.

## PITF-051 — Overflow de int32 en la comprobación de una longitud antes de convertir a int64
**Síntoma**: un check de bounds del tipo `if int64(4+n) > int64(len(b))` con `n` un `int32` leído del input. La suma `4+n` se evalúa en `int32` ANTES de la conversión a int64, así que con `n` cerca de `math.MaxInt32` (p. ej. `0x7fffffff`) desborda a negativo; `int64(negativo)` no supera `len(b)`, el check PASA, y luego se devuelve `4 + int(n)` (ya en int64 = ~2 GiB) como longitud/consumed. El caller usa ese valor para slicear (`b[off:]`) y **panica** (`slice bounds out of range [2147483656:9]`). El fuzz smoke de 30s no lo caza; el fuzz-long de 30m sí.
**Regla**: en un check de longitud, convierte a int64 (o el tipo ancho) CADA operando ANTES de sumar: `if 4+int64(n) > int64(len(b))`, nunca `int64(4+n)`. Y valida el signo (`n < 0`) por separado. Aplica a cualquier `const + valorDelInput` donde el input es int32/int16: haz la aritmética en el tipo ancho desde el principio.
**Ver**: `internal/protocols/opcua/wire/writerequest.go` (`skipLengthPrefixedBytes`), nightly fuzz 30-8-2026.

## PITF-052 — Aserción de test contra una lista/constante copiada a mano que se queda obsoleta
**Síntoma**: un test valida la salida contra una lista de literales copiada del código (`[]string{"PACSystems", ...}`) porque "no se puede importar la lista sin exportar". La lista real crece (nuevas familias) pero la copia del test no; un fuzz encuentra una salida válida (`"PAC9000"`) que la copia obsoleta rechaza → falso fallo. El test comprobaba una copia, no la verdad.
**Regla**: los tests validan contra la fuente real, no una copia. Para exponer un símbolo sin exportar a un `_test` externo, usa el idioma `export_test.go` (`package X` con `var Exported = internal`), accesible solo desde tests. Nunca dupliques a mano una lista/tabla que el código puede crecer.
**Ver**: `internal/protocols/gesrtp/wire/export_test.go`, nightly fuzz 30-8-2026.

## PITF-053: Recursión sin cota en un parser de input de red no confiable
**Síntoma**: un decoder de respuesta (OPC UA `GetEndpointsResponse`) parsea un `DiagnosticInfo`, cuyo bitmask puede pedir un `innerDiagnosticInfo` anidado (bit `0x40`); el parser recursa sin límite de profundidad. Una respuesta hostil que encadena el bit en cada byte fuerza tantos niveles de recursión como bytes tenga, agotando la pila. Como esto parsea la respuesta de un host que se está fingerprinteando (input NO confiable por definición), es un DoS remoto. Ni el build ni los tests unitarios lo ven; lo caza el fuzz al correrlo sobre el propio parser nuevo.
**Regla**: todo parser de input de red no confiable con un campo auto-referente (diagnostics anidados, ExtensionObject, TLV recursivo, etc.) lleva una cota de profundidad explícita y falla cerrado al superarla. Y: fuzz-ea SIEMPRE cada parser nuevo de input no confiable, no solo confíes en tests de casos felices. Cota generosa pero finita (aquí `maxDiagDepth=16`; el anidamiento real es de 1-2 niveles).
**Ver**: `internal/protocols/opcua/wire/getendpoints.go` (`diagnosticInfo(depth)`, `maxDiagDepth`), 1-9-2026.

## PITF-054: Bypass de un write-gate por marcador partido entre lecturas de stream
**Síntoma**: un gate que escanea un stream buscando un marcador de 2 bytes (el magic L7 `0x55cd`/`0x7557` de CoDeSys, cuyo framing L3/L4 no es de longitud fiable) daba por reenviable un byte suelto `0x55`/`0x75` al final del buffer, porque el `matchMagic` necesita los 2 bytes para reconocer el marcador. Si el magic llegaba partido en dos segmentos TCP (`0x55` en un `Read`, `0xcd` en el siguiente), el gate reenviaba cada byte por separado, nunca reconstruía el magic, nunca clasificaba el comando: **la escritura pasaba sin filtrar**. Además, acumular todo el stream y reescanearlo entero en cada `Read` es O(N²) (DoS enviando byte a byte) y rechazaba sesiones legítimas largas al topar el buffer máximo.
**Regla**: en un gate por escaneo de stream, nunca reenvíes un byte que pueda ser el COMIENZO de un marcador aún incompleto: retén cualquier sufijo que sea prefijo (parcial) del marcador, no solo cuando el marcador entero está presente. Y descarta lo ya escaneado-y-reenviado para que cada escaneo sea O(cola), no O(sesión). A fin de stream (EOF) un byte-prefijo suelto ya no puede completar un marcador, así que ahí sí es seguro reenviarlo; solo un marcador emparejado-pero-incompleto es un comando truncado.
**Ver**: `internal/protocols/codesys/wire/categories.go` (`ScanL7`/`magicPrefixAt`), `offensive/write/codesys/gatedproxy.go` (`forward`), 1-9-2026.

## Template para nueva entrada
Ver `.context/templates/pitfall.md`.
