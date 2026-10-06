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

## PITF-001, Counter de sesión no persistido
**Síntoma**: revocación falla tras restart; cookies viejas reviven.
**Regla**: counters de invalidación persisten (BD o fichero).
**Implementación correcta**: tabla `web_state(key, token_generation)`; `UPDATE ... RETURNING` con advisory lock.
**Ver**: ADR-014.

## PITF-002, Ciclo de dependencias en derivación de claves
**Síntoma**: "deriva X del vault; si no hay vault, crea X y cifra con passphrase del vault", sin vault no hay passphrase.
**Regla**: clave dependiente del vault exige vault inicializado; si falta, error claro (no auto-crear).
**Ver**: ADR-017.

## PITF-003, Exit code único para todas las señales
**Síntoma**: SIGINT y SIGTERM devuelven el mismo código.
**Regla**: convención Unix `128 + signum`. SIGINT=130, SIGTERM=143. Segunda señal durante drain → exit inmediato mismo código.

## PITF-004, Redaction con patrones demasiado amplios
**Síntoma**: logs legítimos machacados (`sort_key`, UUIDs).
**Regla**: patrones específicos + heurística de entropía con pre-filter de UUIDs v1-v5.
**Patrones válidos**: `api_key, secret_key, private_key, access_key, session_key, encryption_key, auth_token, refresh_token, bearer_token, password, passphrase, secret, authorization, cookie`.

## PITF-005, Prompt de passphrase en batch
**Síntoma**: scan 1000 targets pide passphrase 1000 veces.
**Regla**: vault unlock-once; master key cacheada en memguard; zeroizada al shutdown o `vault lock`.
**Ver**: ADR-018.

## PITF-006, CGO cross-compile sin toolchains
**Síntoma**: goreleaser con CGO=1 falla cross-compilando.
**Regla**: CGO no cross-compila sin toolchains; variantes CGO solo nativo del runner.

## PITF-007, Referencia rota a versión anterior
**Síntoma**: "ver sección X del v5", lector no tiene v5.
**Regla**: documentos entregables autosuficientes; todo contenido referenciado inline.
**Detector**: `context-check.sh` hace grep de patrones `(versión anterior|del v[0-9]+|mantener del v[0-9]+|sección v[0-9]+ sin cambios)`.

## PITF-008, Asumir comportamiento CLI externo
**Síntoma**: documentar flujo con CLI que no se comporta como dices.
**Regla**: verificar comportamiento real; si duda, alternativa directa (escritura fichero).

## PITF-009, Error tipado mal ubicado
**Síntoma**: errors del paquete X declarados en paquete Y.
**Regla**: sentinels en paquete emisor; `core/errors.go` solo para dominio compartido.

## PITF-010, Config ejemplo desalineada con entorno dev
**Síntoma**: `.env.example` sin password + docker-compose con password → copia directa no conecta.
**Regla**: coherencia `.env.example` ↔ servicios dev; si DSN sin password, servicio con trust auth loopback.

## PITF-011, Dependencia legacy sin verificar estado
**Síntoma**: se referencia lib archivada.
**Regla**: verificar estado de mantenimiento al introducir dep; si archivada, documentar alternativa + PITF.
**Casos**: `google/gopacket` → `gopacket/gopacket`. `mattn/go-sqlcipher` → `mutecomm/go-sqlcipher/v4`. `elastic/go-seccomp-bpf` → verificar en F5.

## PITF-012, Generador no cubre todas las secciones
**Síntoma**: asumir `cobra/doc` genera man1/5/7; solo man1.
**Regla**: man5 y man7 manuales (pandoc); script `gen-manpages.sh` invoca ambas rutas desde `man/src/man{5,7}/*.md`.

## PITF-013, Contenido vacío inválido para generador
**Síntoma**: "vacío F0" → pandoc rechaza.
**Regla**: todo artifact generable tiene contenido mínimo válido.

## PITF-014, Campos JCS no enumerados
**Síntoma**: hash chain JCS sin lista exacta de campos → hashes divergentes.
**Regla**: enumerar campos exactos; excluir derivados.
**Campos audit_log**: `id, occurred_at, actor, event_type, payload, prev_hash`.

## PITF-015, Comando destructivo sin modo batch
**Síntoma**: solo prompt interactivo → no CI/cron.
**Regla**: destructivos con dos modos, interactivo (`YES`) y batch (`--yes` + flag de riesgo `--i-break-the-chain`).

## PITF-016, Secretos via argv o herestring
**Síntoma**: API key queda en shell history y `ps`/`proc/<pid>/cmdline`.
**Regla**: nunca secretos en argv ni herestring; `read -rs` + redirección a fichero + `unset`.
**Implementación correcta**:
```bash
read -rs KEY
printf '%s' "$KEY" > ~/.shodan/api_key
chmod 600 ~/.shodan/api_key
unset KEY
```

## PITF-017, Documento auto-contradictorio
**Síntoma**: regla en sección A violada en sección B del mismo documento.
**Regla**: tras cada edición importante, cross-check reglas contra implementación descrita; resolver o documentar excepción con rationale.

## PITF-018, Referencia a fichero/directorio ausente de la estructura
**Síntoma**: script lee `man/src/` pero la estructura del repo no lo incluye → fallo primera ejecución.
**Regla**: cada path referenciado existe en el árbol; añadir al árbol si se introduce.

## PITF-019, Template incoherente con uso real
**Síntoma**: template formato A; uso real formato B.
**Regla**: template refleja exactamente el formato del uso real.

## PITF-020, Servicio con defaults permisivos sin bind explícito
**Síntoma**: `docker-compose` trust auth publica en `0.0.0.0` → LAN conecta sin password.
**Regla**: servicios con defaults permisivos requieren bind explícito loopback (`127.0.0.1:port:port`).

## PITF-021, Comando que auto-crea estado crítico silenciosamente
**Síntoma**: `serve` auto-inicializa vault → typo passphrase crea vault vacío.
**Regla**: inicialización crítica exige comando explícito (`vault init`); operativos fallan con mensaje claro si estado previo falta.

## PITF-022, Enum-like sin valores enumerados
**Síntoma**: campo config `tls_required=auto` sin definir valores permitidos.
**Regla**: enum-like con enumeración explícita + semántica; validar en parse.
**Casos**: `database.tls_required` ∈ {auto, always, disable}; `audit_log.event_type` CHECK constraint.

## PITF-023, Subprocess con flag injection posible
**Síntoma**: target controlado por input empieza por `-` → subprocess lo interpreta como flag.
**Regla**: separador `--` determinista entre flags y posicionales; `SafeCommand(CommandSpec{Name, Flags, Positional})` lo aplica.
**Ver**: ADR-024.

## PITF-024, Precisión de timestamp inconsistente con storage
**Síntoma**: spec dice "Nano" pero Postgres `TIMESTAMPTZ` es microsegundos → trunca silenciosamente.
**Regla**: alinear precisión código/serialización/storage. Spec dice "RFC3339 con hasta 6 dígitos fracción" (ADR-020).

## PITF-025, Operaciones caras en health checks
**Síntoma**: `/readyz` verifica cadena completa audit → tarda minutos → probe falla → reinicio.
**Regla**: health checks baratos; integridad con muestra limitada controlada por config.
**Casos**: `readyz.audit_tail_entries=100`.

## PITF-026, Race en bump de counter
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

## PITF-027, Reintentos sin límite ni dead-letter
**Síntoma**: `outbox` reintenta para siempre.
**Regla**: `max_attempts` acotado; al agotar, mover a tabla `_dead` con `last_error`.

## PITF-028, Operación reversible sin comando de reversión
**Síntoma**: `vault unlock` sin `vault lock` → reiniciar proceso.
**Regla**: operación reversible sobre estado en memoria tiene comando explícito de reversión (`lock`, `logout`, `stop`).

## PITF-029, Meta-contradicción de reglas
**Síntoma**: el documento aplica una regla en una sección y la viola en otra.
**Regla**: tras cada edición del documento, grep de patrones prohibidos contra el propio documento.
**Detector**:
```bash
grep -nE '(versión anterior|del v[0-9]+|mantener del v[0-9]+)' elsereno-prompt.md && echo VIOLATES || echo ok
```

## PITF-030, Duplicación desincronizada
**Síntoma**: misma enumeración en dos sitios (p. ej. header changelog + SQL CHECK); al editar uno se olvida el otro.
**Regla**: un solo source of truth por enumeración; el resto son derivados marcados como tal.
**Casos**: audit `event_type` SoT = SQL DDL; redaction patterns SoT = `conventions.md`.

## PITF-031, Make ci drift respecto al CI remoto
**Síntoma**: `make ci` local omite jobs que el CI remoto sí corre (builds -tags offensive, fuzz, go-licenses) → bitrot no detectado hasta el push.
**Regla**: `make ci` es superset funcional de los jobs del CI que detectan bitrot (todas las variantes de build + tests + seguridad completa).
**Implementación correcta**: target `ci: lint build build-offensive test-race test-cover test-fuzz sec context-check`. `make sec` incluye `go-licenses check` además de gosec/govulncheck/trivy/gitleaks. Documentar en CONTRIBUTING que `make ci` es aproximación local (el remoto es autoritativo) y aun así cubre el mismo espacio. El variant `-tags sqlite` fue retirado en v1.2.

## PITF-032, Env vars con secretos
**Síntoma**: secretos en env (`ELSERENO_VAULT_PASSPHRASE`, API keys) leakean via `/proc/<pid>/environ` y `ps e`.
**Regla**: secretos persistentes en fichero con 0600 o vault cifrado; env acceptable para CI/cron pero con warning al arrancar si hay TTY (indica que probablemente es uso interactivo por error). Nunca en argv ni herestring.
**Implementación correcta**: en `creds` module, detect `isatty(stderr)` + env var con secreto → imprimir warning recomendando `vault unlock` interactivo o fichero 0600.
**Ver**: ADR-026.

## PITF-033, FK sin ON DELETE action contra entidad hard-deletable
**Síntoma**: tabla A.x referencia B.id sin `ON DELETE`; otro comando hace hard-delete en B → FK violation o row huérfana.
**Regla**: declarar `ON DELETE` action explícito (`CASCADE`, `SET NULL`, `RESTRICT`) y/o una regla dura que impida el hard-delete de la entidad referenciada. Documentar la interacción en el ADR relevante.
**Casos**: `audit_purge_markers.audit_entry_id` → `audit_log(id) ON DELETE RESTRICT` + regla ADR-013 que excluye `event_type IN ('genesis','chain_rebase','purge_event')` del `audit compact`.

## PITF-034, Lectura per-request de estado persistido sin cache
**Síntoma**: middleware web consulta `web_state` en cada request para validar `token_generation` → DB round trip lineal con QPS → saturación pool/latencia.
**Regla**: estados que cambian raramente pero se leen en caliente van detrás de cache con TTL corto (o invalidación por event bus). Aceptar ventana stale acotada.
**Implementación correcta**: `web.token_generation_cache_ttl=5s`. Rotación invalida cookies en ≤TTL segundos, tolerable para caso de uso.

## PITF-035, Tags de imágenes Docker flotantes
**Síntoma**: `image: postgres:16` o `image: adminer` sin tag. Docker Hub mueve la etiqueta; en la siguiente reconstrucción aparece una versión distinta y las migraciones/feature flags divergen silenciosamente entre máquinas o entre CI y local.
**Regla**: pin exacto en la etiqueta (`postgres:16.3-alpine3.20`, `adminer:4.8.1`) y preferible también pinear el digest `@sha256:…` en contextos prod. Actualizar tag es cambio explícito con PR, no deriva.
**Implementación correcta**: `docker-compose.dev.yml` usa tags exactos; `Dockerfile` builder stage también pinneado (`golang:1.23.4-alpine3.20`). Esto es variante contenedor de PITF-011.

## PITF-036, Detector auto-referencial
**Síntoma**: un script lint/detector contiene como string los patrones que busca. Al ejecutarlo sobre el árbol completo, se detecta a sí mismo (o a la documentación que los define, como `pitfalls.md`) y siempre falla.
**Regla**: detectores que buscan patrones textuales excluyen los ficheros donde los patrones se definen (típicamente `pitfalls.md` y el propio script) **y** ignoran bloques de código (fences triple-backtick).
**Implementación correcta**: awk que alterna un flag `in_code` al ver `^```` y solo matchea fuera; `find` con `! -name pitfalls.md`. Verificado contra el propio catálogo antes de comitear.

## PITF-037, Enviar a un canal que otra goroutine puede cerrar
**Síntoma**: `panic: send on closed channel` intermitente bajo carga. Un fan-out toma un snapshot de subscribers, suelta el lock y envía fuera de él, mientras un `cancel` cierra ese canal. Si el pánico ocurre en una goroutine sin `recover` (worker, scheduler, observer), cae el proceso entero.
**Regla**: nunca cerrar un canal que puede tener varios emisores sin sincronización. O bien (a) el envío y el `close` son mutuamente exclusivos bajo el mismo `RWMutex` (envío bajo `RLock` con `select ... default` no bloqueante; `close` bajo `Lock`), o bien (b) no se cierra nunca el canal de datos y se señaliza el fin con un `done chan struct{}` cerrado una sola vez (`sync.Once`), que los emisores observan con `select { case ch <- v: case <-done: default: }`.
**Ver**: broadcaster SSE, commit c441eb4.

## PITF-038, Leer estado compartido tras un `Handle` que no hace join
**Síntoma**: un `Handle` lanza goroutines y retorna al primer error o a `ctx.Done()` sin esperar a que todas terminen; un llamador lee después un contador/veredicto que una goroutine superviviente sigue mutando. Data race (lo caza `go test -race`) y lectura sobre estado parcial.
**Regla**: el estado compartido entre la goroutine de trabajo y el lector se protege con mutex/atómicos, o el `Handle` hace join (`WaitGroup` / drenar todas las entradas del canal de errores) antes de exponer el resultado. Un comentario que dice "leer solo tras terminar" no es sincronización.
**Ver**: gatedproxy ENIP `obs`, commit c441eb4.

## PITF-039, Familia de función que "straddlea" read/write sin gate por subcódigo
**Síntoma**: una matriz allow/deny clasifica una familia entera (Modbus FC8 Diagnostics, MEI, un servicio CIP contenedor) como una sola categoría y la reenvía o bloquea en bloque. Dentro hay subcódigos que mutan estado (Force Listen Only, Restart, Clear Counters), así que el write-ban por defecto deja pasar un DoS al equipo pese a prometer read-only.
**Regla**: toda familia cuyos subcódigos crucen la frontera read/write se clasifica **por subcódigo**, no por familia. Por defecto (read-only) solo pasan los subcódigos de lectura pura; un frame corto/malformado se bloquea (fail-closed). En build ofensivo la subfamília peligrosa exige estar en el allowlist con su subcódigo.
**Ver**: Modbus FC8, commit c6bdf38.

## PITF-040, Paginar por el recuento filtrado en vez del crudo
**Síntoma**: un paginador para cuando una página devuelve menos elementos de los pedidos, pero el recuento se toma **después** de filtrar filas inválidas (IP/puerto no parseables, IPv6 no soportado). Una página con unas pocas filas descartadas parece "fin del dataset" y se truncan en silencio las páginas siguientes.
**Regla**: la condición de terminación de la paginación se decide con el recuento **crudo** de la respuesta (`len(parsed.Matches)`), nunca con el recuento tras filtrar. Devolver ambos si hace falta.
**Ver**: Shodan/FOFA `SearchPaged`, commit c6bdf38.

## PITF-041, `io.ReadAll` sin límite en la ruta no confiable
**Síntoma**: un proxy/handler bufferiza un cuerpo con `io.ReadAll(req.Body)` para inspeccionarlo. Un POST gigante o un stream chunked que no termina agota la memoria del proceso (DoS), justo en el componente inline que se sitúa delante del equipo protegido.
**Regla**: acotar toda lectura de datos no confiables con `io.LimitReader(r, max+1)` (o `http.MaxBytesReader`) y **rechazar** lo que exceda, no truncar y reenviar (un cuerpo truncado corrompe la request aguas arriba). El tope se comparte con el de los proxies hermanos (p. ej. 1 MiB).
**Ver**: proxy CWMP, commit c6bdf38.

## PITF-042, Parser de detección ciego al formato dominante real
**Síntoma**: un clasificador/scorer solo reconoce una codificación minoritaria de un campo (segmentos lógicos de clase) y rechaza la que usa el tráfico real más común (segmento simbólico ANSI `0x91` con nombre de tag en Logix). La regla anti-falso-positivo produce entonces el falso negativo que pretendía evitar: el veredicto queda "limpio/ciego" ante escrituras reales.
**Regla**: un parser cuyo propósito es detección debe cubrir los formatos que el objetivo usa de verdad, no solo el del spec-book. Verificar contra el tráfico dominante del vendor. Para el gate (fail-closed) rechazar lo no clasificado está bien; para la detección/scoring, no reconocerlo es un fallo de cobertura.
**Ver**: EPATH segmento simbólico `0x91`, commit c441eb4.

## PITF-043, Gate de rango que solo valida la dirección de inicio
**Síntoma**: una allowlist por rango comprueba solo la dirección de arranque de una escritura múltiple e ignora la cantidad. Una escritura que empieza en el borde superior del rango autorizado se sale por arriba (`start ∈ [lo,hi]` pero `start+qty-1 > hi`).
**Regla**: para operaciones de rango (write multiple, read-write) validar **ambos** extremos, `start` y `start+qty-1`, y rechazar un rango que desborde el espacio de direcciones (calcular en un entero más ancho para detectar el wrap).
**Ver**: gate Modbus por rango, commit c6bdf38.

## PITF-044, Auth fail-open en bind de red
**Síntoma**: un servidor exige TLS y un flag explícito para escuchar en una dirección no-loopback, pero **no** exige autenticación real; en modo DEV la identidad del operador se toma de una cabecera falsificable (`X-Operator`). La API queda expuesta a la red sin auth, solo con un aviso por stderr.
**Regla**: exponer una API a la red (bind no-loopback) exige autenticación real habilitada (OIDC), además de TLS. Sin ella, rechazar el arranque. La identidad DEV por cabecera solo vale en loopback.
**Ver**: `serve` `validateBindSecurity`, commit 64898cb.

## PITF-045, Constante de protocolo incorrecta y desalineación de parser
**Síntoma**: un id/tipo de campo mal transcrito (CPF Connected Data Item como `0x00A2` cuando el estándar es `0x00B1`) hace que una rama sea código muerto y otra nunca se reconozca; además el item conectado prefija bytes (sequence count) que el parser no salta, dejándolo desalineado respecto a lo que el dispositivo ejecuta. Efecto colateral: differential de parser (el gate ve una ruta, el equipo otra) y allowlist que nunca admite el caso conectado.
**Regla**: las constantes de protocolo se cotejan contra la fuente normativa (ODVA CIP Vol 2, etc.), no contra la memoria; los prefijos por-variante (sequence count, padding) se saltan explícitamente antes de parsear el cuerpo. Un test cubre la variante conectada además de la no conectada.
**Ver**: CPF `0x00B1`, commit c441eb4.

## PITF-046, Extraer un archivo sin guard de path traversal
**Síntoma**: al restaurar un backup/tar se hace `join(destDir, member.Name)` sin validar `member.Name`; un `../` escribe fuera del directorio destino. Que el archivo esté cifrado/autenticado mitiga (solo un insider con la clave lo explota) pero no exime.
**Regla**: todo nombre de miembro de un archivo se valida antes de escribir: `filepath.Join` + comprobar que el resultado sigue bajo el directorio destino limpio (`dst == dir || strings.HasPrefix(dst, dir+sep)`); rechazar lo que se salga. Defensa en profundidad barata.
**Ver**: restore de backup, commit 64898cb.

## PITF-047, Componer dos programas BPF/cBPF terminales concatenándolos
**Síntoma**: se construye un filtro seccomp uniendo un sub-programa de arg-filter (que ya acaba en `RET ALLOW` + `RET ERRNO`) delante del programa de denylist de syscalls. Como seccomp evalúa UN único programa lineal y para en el primer `RET`, cualquier syscall que no case con el arg-filter cae al `RET ALLOW` intermedio y retorna ALLOW: toda la denylist de syscalls que va detrás queda como código muerto e inalcanzable. Agravado por un off-by-one en los saltos de "deny" (aterrizan en `RET ALLOW` en vez de `RET ERRNO`). El resultado da falsa garantía de aislamiento (`Available=true, kind=seccomp-bpf`) sin bloquear nada.
**Regla**: un filtro cBPF es un solo programa con UNA cola compartida. No concatenar dos programas cada uno con su `RET`. Construir un único programa (arch-check primero, denylist, luego bloques de arg-rules) y calcular CADA salto desde el índice absoluto de la instrucción al índice absoluto del `RET ERRNO` final (`offset = destino - origen - 1`), nunca con "distancias" relativas propensas al off-by-one. Los caminos "deny" saltan al `RET ERRNO`; los "allow" caen por fall-through al `RET ALLOW`.
**Verificación obligatoria**: un test que EJECUTE el programa compilado (intérprete cBPF o instalación real del filtro) y afirme el veredicto `SECCOMP_RET_*` por caso: la denylist deniega (no basta que exista), el arg-rule deniega el valor malo y permite el bueno, arch incorrecta mata. Un test que solo comprueba longitud y campo `K` NO detecta ni la denylist muerta ni el off-by-one de `Jt`/`Jf`. Y el código de test debe ejecutarse en CI: si el job de tests corre `go test ./...` sin el build-tag que compila esos ficheros (p. ej. `-tags offensive`), el test existe pero nunca corre y el bug pasa igual.
**Ver**: `offensive/sandbox/bpf_argfilter_linux.go` (`compileCombinedFilter`), re-auditoría 29-8-2026.

## PITF-048, Llamar "tamper-proof" a un hash chain sin clave
**Síntoma**: una cadena de auditoría calcula `entry_hash = SHA-256(canonical(entry))` y se documenta como a prueba de manipulación. No lo es: cualquiera con acceso de escritura al log edita una entrada y **recomputa toda la cadena hacia delante** (los hashes son públicos), y `Verify` pasa. Es tamper-EVIDENT (detecta ediciones accidentales), no tamper-PROOF.
**Regla**: para tamper-proof, la entrada se firma con una clave que el atacante no tiene: `entry_hash = HMAC-SHA256(clave_derivada_del_vault, canonical(entry))`. Si el log se escribe desde contextos heterogéneos (unos con la clave, otros sin ella: p. ej. operaciones de escritura con vault vs. harvest de solo lectura sin vault), NO fuerces a todos a tener la clave ni partas el fichero: usa HMAC donde puedas y SHA-256 donde no, en la misma cadena. El `prev_hash` las ata: cada entrada firmada cubre el `prev_hash` (= hash de la anterior), así que manipular CUALQUIER entrada anterior rompe el `prev_hash` de la siguiente entrada firmada, que el atacante no puede recomputar. La cadena queda tamper-proof hasta la última entrada firmada. La verificación "prueba HMAC o SHA-256" no habilita downgrade por esa misma razón (la siguiente entrada firmada lo caza). Deriva la clave con dominio propio (`Vault.Derive("elsereno/audit/hmac/v1", …)`).
**Ver**: `internal/audit/canonical.go` (`computeHash`/`verifyEntry`), re-auditoría 30-8-2026.

## PITF-049, Escritor con estado cacheado sin lock inter-proceso cuando un hermano sí lo tiene
**Síntoma**: dos implementaciones del mismo escritor serializado (p. ej. `FileWriter` con `flock` y `DBWriter` con solo un mutex de struct). El que solo tiene mutex cachea el estado de encadenamiento (`prevHash`) y lo lee una vez; dos procesos leen el mismo último hash y encadenan desde él, **bifurcando la cadena**. El código ya conocía la primitiva correcta (advisory locks de Postgres usados en otra parte) pero este escritor no la usaba.
**Regla**: si un invariante exige serializar lecturas-luego-escrituras entre procesos, TODAS las rutas de persistencia necesitan el equivalente. Para Postgres con pool: una transacción con `pg_advisory_xact_lock(key)` y **re-leer el estado más reciente DENTRO del lock** en cada operación (no confiar en la caché sembrada una vez). Type-assert el conn a una interfaz `BeginTx` opcional para que producción (pool) tome el lock y los fakes de test caigan a la ruta sin lock.
**Ver**: `internal/audit/dbwriter.go` (`appendLocked`), re-auditoría 30-8-2026.

## PITF-050, Acotar la entrada en un transporte y olvidarlo en el hermano
**Síntoma**: un parser de red pone un tope de bytes en la ruta UDP (p. ej. `make([]byte, 4096)` + un `Read`) pero pasa el `net.Conn` crudo al parser en la ruta TCP. Sobre TCP, `bufio.ReadString`/`textproto.ReadMIMEHeader` crecen la asignación con lo que el peer envíe hasta un `\n`/línea en blanco, acotados solo por el deadline de I/O: un host que transmite una línea de estado o un bloque de cabeceras interminable amplifica memoria/GC, repetible en un barrido. El tope de UDP oculta que TCP no tiene ninguno.
**Regla**: cuando el mismo parser sirve varios transportes, la cota de entrada va en TODOS. Para streams (TCP), envuelve la conexión con `io.LimitReader(conn, N)` antes de parsear, con N generoso pero finito (mayor que cualquier mensaje legítimo). No confíes solo en el deadline como límite de tamaño: acota bytes Y tiempo.
**Ver**: `internal/protocols/sip/sip.go` (`maxTCPResponseBytes`), re-auditoría 30-8-2026.

## PITF-051, Overflow de int32 en la comprobación de una longitud antes de convertir a int64
**Síntoma**: un check de bounds del tipo `if int64(4+n) > int64(len(b))` con `n` un `int32` leído del input. La suma `4+n` se evalúa en `int32` ANTES de la conversión a int64, así que con `n` cerca de `math.MaxInt32` (p. ej. `0x7fffffff`) desborda a negativo; `int64(negativo)` no supera `len(b)`, el check PASA, y luego se devuelve `4 + int(n)` (ya en int64 = ~2 GiB) como longitud/consumed. El caller usa ese valor para slicear (`b[off:]`) y **panica** (`slice bounds out of range [2147483656:9]`). El fuzz smoke de 30s no lo caza; el fuzz-long de 30m sí.
**Regla**: en un check de longitud, convierte a int64 (o el tipo ancho) CADA operando ANTES de sumar: `if 4+int64(n) > int64(len(b))`, nunca `int64(4+n)`. Y valida el signo (`n < 0`) por separado. Aplica a cualquier `const + valorDelInput` donde el input es int32/int16: haz la aritmética en el tipo ancho desde el principio.
**Ver**: `internal/protocols/opcua/wire/writerequest.go` (`skipLengthPrefixedBytes`), nightly fuzz 30-8-2026.

## PITF-052, Aserción de test contra una lista/constante copiada a mano que se queda obsoleta
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

## PITF-055: Firma GPG con `git rebase --exec` deja la rama en un rebase interrumpido que PARECE pérdida de commits
**Síntoma**: firmar una tanda con `git rebase --exec 'git commit --amend --no-edit -S' <base>` puede colgarse en el `pinentry` de GPG DENTRO del rebase (el TTY del exec no siempre puede pedir la passphrase). El rebase se queda a medias: `HEAD` se sienta en el PRIMER commit re-pickeado y los demás (fix, docs...) desaparecen del historial visible; `git log` engaña y da la sensación de que se perdió el trabajo. Queda un `.git/rebase-merge` (o `rebase-apply`).
**Regla**: NO entres en pánico ni hagas `reset --hard` a ciegas. (1) Comprueba `ls .git/rebase-merge .git/rebase-apply` y `git reflog`; los commits "perdidos" siguen ahí (p. ej. el tip de la rama en `HEAD@{1}`). (2) **`git rebase --abort`** restaura la rama completa intacta. (3) Para firmar de verdad, **calienta el gpg-agent en primer plano ANTES** del rebase: `echo warm | gpg --local-user <KEY> --clearsign >/dev/null`, y solo entonces `git rebase --exec ... <base>`; o firma commit a commit. El build loop NUNCA corre GPG; firma el conductor.
**Ver**: recuperación de la rama `feat/deepteam-...` de Il Dottore, 2-9-2026 (mismo patrón de pinentry que ya vimos aquí con el warmup).

## PITF-056: Detectar em/en dashes con `grep $'-'` en zsh da falsos "0 rayas"
**Síntoma**: para verificar que no queda ninguna raya larga (regla de Daniel: nunca `-`/`-` en texto producido), un `grep -l $'-\|-'` en zsh **no casa nada silenciosamente** (el `$'…'` con el glifo no se expande como se espera) y reporta "0 rayas" en falso. Se dieron por buenas varias verificaciones equivocadas.
**Regla**: detecta rayas con **Python** (`sum(1 for l in ... if "-" in l or "-" in l)`), no con `grep $'…'` en zsh. Escanea las líneas AÑADIDAS del diff (no ficheros enteros: las rayas preexistentes del repo no son tuyas). Relacionado: zsh tampoco hace word-splitting de variables/`$(...)` sin comillas → usa `xargs` o arrays para comandos git multi-fichero.
**Ver**: Il Dottore docs/rama, 2-9-2026.

## PITF-057: La cwd de la sesión NO es el repo (se pierde de vista dónde aterriza el trabajo)
**Síntoma**: una sesión puede arrancar en una carpeta ajena (p. ej. `~/Downloads/<hash>/...`), NO en el repo. Como el estado del shell no persiste entre llamadas de herramienta (la cwd se resetea tras cada comando), es fácil dar por hecho que "estamos en el repo" cuando no. El trabajo se hace bien si cada comando entra al repo, pero al reportar estado ("hecho", ramas, hashes) sin nombrar la ruta, Daniel duda de si los commits cayeron donde debían (pasó el 3-9-2026: "pero no estamos en ildottore?").
**Regla**: (1) los repos de Daniel viven en `~/AI projects/` (`elSereno` Go, `ildottore` Python; la ruta lleva un espacio, entre comillas). (2) `cd "$HOME/AI projects/<repo>"` en CADA cadena de comandos, no una sola vez. (3) Al informar de estado, escribe la **ruta absoluta del repo** de forma explícita, no solo el nombre. (4) Ante la mínima duda, `pwd` + `git rev-parse --show-toplevel` antes de afirmar nada.
**Ver**: Il Dottore, 3-9-2026.

## PITF-058: Tratar una familia de comandos "de diagnóstico" como benigna en bloque
**Síntoma**: el write-gate de Modbus clasificaba FC 8 (Diagnostics) como una categoría permisiva y reenviaba TODAS sus sub-funciones (`return true` con el comentario "per-sub-code gating tracked for F-future"). Pero FC 8 mezcla lecturas inocuas (Return Query Data 0x00, contadores 0x0B-0x12) con acciones mutantes graves: Force Listen Only (0x04) SILENCIA el esclavo (DoS: deja de responder al bus), Clear Counters (0x0A) BORRA los contadores forenses, Restart (0x01) reinicia el equipo. Un allowlist de escrituras estrecho no protegía de nada de esto porque la sub-función viajaba por otra rama del gate. El propio código lo confesaba en un comentario y aun así estaba en producción.
**Regla**: una "familia de diagnóstico" no es una categoría de confianza; ábrela por sub-función con **allowlist de solo-lectura** (lista blanca, no negra: lo desconocido/reservado se DENIEGA), y las mutantes solo con opt-in explícito del operador atado al token. Cuando un campo de 16 bits decide entre "eco/contador" y "silenciar/borrar el equipo", el default es denegar. Y si tu propio comentario dice "por ahora permisivo, se endurece en F-futuro", eso es una vulnerabilidad viva, no una TODO: trátala como bug de seguridad. Backwards-compat del token: pliega el nuevo allowlist en el hash SOLO si no está vacío, para no invalidar los tokens de quien no usa la dimensión nueva.
**Ver**: `internal/protocols/modbus/wire/codes.go` (`DiagIsReadOnly`, `DiagSubFunction`), `offensive/write/modbus/gatedproxy.go` (`shouldForward` caso `CategoryDiagnostic`, `AllowlistHashWithDiag`), 3-9-2026.

## PITF-059: Enmarcar un protocolo leyendo su campo Length cuando el cable lleva CRCs intercalados
**Síntoma**: el write-gate de DNP3 leía `Length-5` bytes de user-data y los daba por el cuerpo entero. Pero en DNP3 (IEEE 1815) el campo Length cuenta ctrl+dest+src+userdata y EXCLUYE los CRC, y el cable transmite un CRC de 2 bytes tras CADA bloque de <=16 octetos de user-data. Al leer solo `Length-5`, el gate dejaba los 2+ bytes de CRC de bloque sin consumir; el siguiente `ReadFull` de cabecera arrancaba descuadrado, no casaba `05 64` y tiraba la conexión. Solo funcionaba con frames sin user-data (reset/test-link). Los tests unitarios NO lo veían porque fabricaban frames SIN los CRC de bloque, es decir, con el mismo error que el parser: dos errores que se cancelan y "pasa verde". Además, el hash del token solo ligaba los FC de enlace, no el allowlist de FC de aplicación (lo que de verdad abre un Operate/Write), así que el confirm-token no cubría las mutaciones que autorizaba.
**Regla**: para enmarcar un protocolo con CRC (o cualquier framing) intercalado por bloques, calcula el tamaño REAL en cable (userdata + CRCs por bloque), no el campo Length a secas; des-bloquea (verifica cada CRC, falla cerrado en mismatch) para inspeccionar, y reenvía los bytes crudos verbatim. Nunca construyas los frames de test con el mismo atajo que el parser: un test que fabrica el frame mal valida el bug, no el código; cruza contra un cliente/dissector independiente o contra un vector catalogado (aquí CRC-16/DNP de "123456789" = 0xEA82). Y el token de sesión debe ligar TODAS las dimensiones que ensanchan lo que el gate reenvía (FC de aplicación, scope de CROB, pin de link-address), no solo la capa de enlace: un token que liga media política es una falsa sensación de seguridad. Corolario del CROB: en un protocolo de control donde un byte lleva la intención (0x81=TRIP, 0x41=CLOSE, 0x03=LATCH), gatea ESE byte y el índice de punto, no solo el function code.
**Ver**: `internal/protocols/dnp3/wire/crc.go` (`CRC16`, `BodyLen`, `StripBlockCRCs`), `internal/protocols/dnp3/wire/control.go` (`ExtractCROBs`, `IsBroadcast`), `offensive/write/dnp3/handle.go` (`forward`/`shouldForward`), `offensive/write/dnp3/gatedproxy.go` (`AllowlistHash`), 22-9-2026.

## PITF-060: Un mismo protocolo con DOS transportes (opc.tcp vs opc.https) donde el cuerpo del mensaje cambia de offset
**Síntoma**: OPC UA lleva el MISMO mensaje de servicio en dos bindings. En `opc.tcp` (Part 6 §7.1) el cuerpo del MSG va precedido de 16 bytes de framing de SecureChannel (SecureChannelId + TokenId + SequenceNumber + RequestId) y el TypeId del servicio cae en offset 16. En el binding HTTPS (§7.4) el POST lleva el mensaje "pelado": el TypeId está en offset 0, sin ese prefijo. Los parsers validados (`ServiceTypeID`, `WriteRequestAllNodesRich`, `CallRequestAllMethods`) asumen `headerPrefix = 16`, así que aplicados directos al body HTTPS leen basura (o fallan cerrado) y el gate no clasificaría el WriteRequest. La tentación es forkear los parsers para el offset nuevo: se duplica lógica de seguridad crítica y se arriesga a que las dos copias deriven.
**Regla**: cuando un transporte solo difiere de otro por un prefijo fijo, NO forkees el parser: adáptalo. Aquí basta con anteponer 16 bytes cero al body HTTPS (`spliceTCPPrefix`) y delegar en el parser TCP ya fuzzeado; los bytes del prefijo nunca se leen por su valor, así que son relleno seguro. Un test de consistencia cierra el contrato: `ServiceTypeIDHTTPS(bare)` debe dar exactamente lo mismo que `ServiceTypeID(prefijo||bare)`. Corolario de scope de token: aunque el allowlist (servicios/NodeIds/métodos) sea idéntico entre transportes, el confirm-token debe ir scoped por transporte (campo `Protocol` distinto: "opcua" vs "opcuahttps"), porque un mismo permiso sobre TCP no implica el mismo permiso sobre HTTPS (distinta exposición). Corolario de refusal: en un binding sobre HTTP, el rechazo nativo del protocolo (UA ServiceFault) viaja como cuerpo de un HTTP 200, no como un 4xx: el transporte HTTP tuvo éxito, el servicio UA falló.
**Ver**: `internal/protocols/opcua/wire/https.go` (`spliceTCPPrefix`, `ServiceTypeIDHTTPS`, `EncodeServiceFaultHTTPS`), `offensive/write/opcuahttps/gatedproxy.go` (`gate`, `writeServiceFaultHTTP`), `internal/protocols/opcua/wire/https_test.go` (`TestHTTPSMatchesTCP`), 23-9-2026.

## PITF-061: Un bump de Dependabot sube el `go` directive de go.mod y desincroniza el resto de sitios que fijan la versión (y arrastra cambios de API que solo rompen bajo build tags concretos)
**Síntoma (21/22-9-2026, se comió una noche entera)**: el bump de pgx 5.11 subió `go.mod` a `go 1.26.0` / `toolchain go1.26.6`, pero el `Dockerfile` (`ARG GO_VERSION`) y la matriz mínima de `ci.yml` seguían en 1.25. El job `build-default (ubuntu-latest, 1.25)` reventó con `go.mod requires go >= 1.26.0 (running go 1.25.x; GOTOOLCHAIN=local)`. En LOCAL no se veía: el toolchain del host era 1.26, que auto-satisface el directive, y `GOTOOLCHAIN=local` en CI es el único sitio donde un Go más viejo NO se auto-actualiza y por tanto falla. El mismo bump arrastró además cambios de API que solo rompían en compilaciones concretas: pgx v5.11 añadió `Rows.TypeMap()` (rompía mocks de `pgx.Rows` en tests), y Go 1.26 deprecó `ecdsa.PublicKey.X/Y` (rompía `parseECJWK` bajo el linter/build de `sec`). Ninguno lo veía un `go build ./...` a secas.
**Regla**: (1) cualquier versión fijada en más de un sitio necesita un check que FALLE ante la deriva, no un comentario que la documente: `scripts/check-version-sync.sh` cruza go.mod ↔ Dockerfile ↔ matriz mínima de ci.yml y corre dentro del job `audit`. Si añades un tercer sitio que fije la versión, mételo en ese check. (2) Tras CUALQUIER bump de dependencia, no basta con `go build` en el toolchain del host: reproduce las variantes que CI ejercita (`go build ./...`, `go build -tags offensive ./...`, `go test ./...`, y mentalmente la matriz de Go mínima), porque el host auto-satisface el directive y esconde el fallo. (3) Un bump de una lib de datos (pgx) o del toolchain puede introducir métodos nuevos en interfaces que implementas por mock, o deprecar API: si tras un bump un paquete no compila bajo un tag que no sueles construir (`sec`, `offensive`), es esto. Cross-ref: PITF-006 (CGO cross-compile), y el `go 1.26` directive obliga a subir Dockerfile+matriz a la vez.
**Ver**: `scripts/check-version-sync.sh`, `.github/workflows/audit.yml` (job `audit` corre `audit.sh --ci`), commits `315eb35` (matriz+Dockerfile), `fe0c91b` (pgx TypeMap + ecdsa), `1bdfb5c` (el check), 23-9-2026.

## PITF-062: Branch protection que enumera nombres de job individuales es frágil (un rename saca el job de la protección en silencio)
**Síntoma**: la protección de `main` exigía 9 checks por nombre exacto (`lint`, `unit (race + coverage)`, `offensive tests (sandbox seccomp)`, ...). Si se renombra o se mueve un job, GitHub sigue exigiendo el nombre viejo (que ya nadie reporta) y lo trata como "no ha fallado", así que el job renombrado deja de ser bloqueante sin que nadie se entere: la protección parece verde pero ya no cubre lo que crees.
**Regla**: gatea con UN job agregador (`ci-passed`) que haga `needs:` de todos los demás por nombre y falle si cualquiera no terminó en `success` (tratando `skipped`/`cancelled` como fallo salvo los jobs legítimamente condicionales, que se dejan fuera del `needs`). La branch protection exige solo ese agregador (más los checks de OTROS workflows, que no pueden ser `needs:` de un job de ci.yml, p.ej. `audit`). Así un nombre obsoleto en `needs` rompe la carga del workflow EN VOZ ALTA en vez de degradar la protección en silencio. `main` exige hoy `[ci-passed, audit]`.
**Ver**: `.github/workflows/ci.yml` (job `ci-passed`), commit `158a3f9`, `gh api .../branches/main/protection/required_status_checks`, 23-9-2026.

## PITF-063: Descubrir los mismos hallazgos de golangci-lint al final de cada feature (post-commit) en vez de antes
**Síntoma**: en cada feature nueva reaparecen las MISMAS clases de lint y se arreglan tarde (tras probar y commitear), forzando un ciclo extra de fix + re-commit. En esta sesión salieron 8 hallazgos post-hoc repartidos entre dos features, todos de un puñado de clases conocidas.
**Regla**: correr `golangci-lint run` sobre los paquetes tocados (y `--build-tags offensive` si el código lleva ese tag) ANTES del primer commit. Las clases recurrentes en este repo y su fix canónico:
- **gosec G115** (conversión int a tipo más estrecho, incl. bit-reinterpretación): `// #nosec G115 -- <razón>` en la MISMA línea de la conversión, o reestructurar; en tests con valores acotados, poner la cota explícita y el nosec.
- **unparam** (un parámetro recibe siempre el mismo valor): quitar el parámetro.
- **errorlint** (`err == ErrX`): usar `errors.Is(err, ErrX)`.
- **gocritic appendAssign** (`x := append(y, ...)` con `x != y`): construir slice nuevo (`make([]T,0,n)` + append) en vez de reusar `y`.
- **revive stutter** (nombre de tipo repite el paquete, p.ej. `goose.GoosePDU`): quitar el prefijo (`goose.PDU`). Ver PITF-059 histórico (`WireBodyLen` → `BodyLen`).
- **gocyclo>15 / funlen>40**: extraer helpers (patrón `applyXField`, `xStatefulChecks`).
- **misspell**: ortografía británica (`synchronise`, no `synchronize`).
Y recuerda: el job `context` exige `.context/STATE.md` <= 250 líneas (recorta entradas de ciclos cerrados viejos al añadir); PITF-056 para detectar em/en dashes de forma fiable; el repo tiene `commit.gpgsign=true`, así que un commit normal intenta firmar (usa `--no-gpg-sign` cuando quien firma es Daniel, no Claude).
**Versión de golangci (crítico, PITF-031): la divergencia va en LOS DOS SENTIDOS.** El job `audit` fija **v2.11.4** (`audit.yml`) mientras `ci` usa **`latest`**. No hay un "más estricto" fijo: cada versión caza cosas que la otra no.
- **v2.11.4 > latest (28-9-2026):** v2.11.4 marcó `G115 int->uint` en `uint(s.frames)` que `latest` (v2.13.2) y mi local NO marcaban; `main` quedó con `audit` en rojo tras un push ya firmado.
- **latest > v2.11.4 (29-9-2026):** al revés. Linté local con v2.11.4 (0 issues) y `audit` pasó, pero `ci` (`latest` = **v2.14.0**, publicado ese día) falló en el job `lint` con `unparam: putSymmetricHeader - b always receives nil` (`internal/protocols/opcua/wire/session.go`): un parámetro que TODOS los callers pasaban `nil`, que el `unparam` de v2.14.0 detecta y el de v2.11.4 no. Fix: quitar el parámetro inútil. `main` quedó con `ci` en rojo tras el push firmado.

**Regla: antes de un push a `main`, lint con las DOS versiones.** Instalar ambas y correr las dos sobre `./...`:
`curl -sSfL .../golangci-lint/master/install.sh | sh -s -- -b /tmp/glci2114 v2.11.4` (audit) y para `latest`, si el install.sh da checksum mismatch (pasó el 29-9 con v2.14.0), usar `GOBIN=/tmp/glciLatest go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest`. Que una pase NO garantiza la otra, en ninguna dirección. Y `latest` se mueve: v2.13.2 el 28-9, v2.14.0 el 29-9.
**Ver**: `.golangci.yml`, `.github/workflows/audit.yml` (pin v2.11.4), `scripts/context-check.sh`, `.context/_quickref.md`, 23-9 y 28-9-2026.

## PITF-064: Un parser construido sobre un fixture fabricado coincide consigo mismo pero no con el protocolo real
**Síntoma**: `DeviceIDObjects` (Modbus FC43/14) tenía una cabecera de respuesta de **6 bytes** y leía `numberOfObjects` de `pdu[5]`, con un test cuyo fixture estaba fabricado a esa misma cabecera de 6 bytes. Test verde, fuzz verde, pero contra una respuesta real (2-10-2026) devolvía **0 objetos**: el spec Modbus V1.1b3 §6.21 tiene **7 bytes** de cabecera (FC, MEI, **Read Device ID code**, Conformity, MoreFollows, NextObjId, NumObjects), el parser se saltaba el "Read Device ID code" y leía `numberOfObjects` del offset de `NextObjId` (0x00). El enriquecimiento Vendor/Product/Revision del probe Modbus salía vacío para todo dispositivo real.
**Causa raíz**: el parser y su fixture se escribieron a la vez desde una lectura equivocada del spec, así que se validaban mutuamente. Un test no prueba nada si su entrada se fabricó para encajar con el código, no con el protocolo. Es PITF-059 ("no fabricar wire, validar contra captura real") visto desde el otro lado: el fixture fabricado no solo no valida, oculta el bug.
**Regla**: todo parser de respuesta de protocolo lleva **al menos un test con bytes de una captura real**, byte a byte, no solo fixtures construidos a mano. Cuando no haya captura, decirlo en el test/commit y tratar el parser como no validado (no como correcto). Al traer una captura real a un parser que ya tenía tests, re-verificar el layout campo a campo contra el spec antes de dar por bueno el test viejo.
**Cómo se cazó**: captura real `modbus_example.pcap` (CISA cisagov/icsnpp-modbus, pkt 94): `2b0e01 83 00 00 03` + 3 objetos ("Zeek Modbus Test" / "Protocol Parsing is fun!" / "1.2.3.6"). Fix: cabecera a 7 bytes, `numberOfObjects=pdu[6]`, objetos en `off=7`; test reescrito con los bytes reales.
**Ver**: `internal/protocols/modbus/wire/mbap.go` (`DeviceIDObjects`), `internal/protocols/modbus/wire/wire_test.go`, 2-10-2026.

## PITF-065: Segundo caso del mismo patrón (fixture fabricado) en Omron FINS
**Síntoma**: `finsudp.ParseControllerDataRead` leía bytes 54..73 como un campo `SystemVersion`, con un fixture de test que ponía ahí un string plausible ("1.04 SYS"). Contra una respuesta real (Omron CP1L-EL20DR-D, 3-10-2026) ese rango resultó ser el área **reservada "For System Use"** (Omron W421 §5.4 y el analizador Spicy de CISA: Model 20, Controller Version 20, For System Use 40 reservados): un dispositivo real devolvía basura en `SystemVersion`.
**Causa raíz**: idéntica a PITF-064. El fixture se fabricó al layout equivocado del parser, así que se validaban mutuamente. Es el **segundo** caso en la misma campaña, lo que confirma que es un patrón del repo, no una anécdota: varios parsers de respuesta se escribieron sobre fixtures crafteados y nunca contra captura real.
**Fix**: eliminado el campo `SystemVersion` (no existe tercera versión; 54..93 es reservado). `Model` e `InternalCode` (Controller Version) se mantienen, validados contra el CP1L real. El probe solo surfaceaba `Model`, así que la basura no llegaba al finding, pero el parser público estaba mal.
**Regla (refuerza PITF-064)**: cuando un parser de respuesta tenga un campo que "a veces viene vacío / es opcional / solo en CPUs nuevos", sospechar: suele ser un área reservada malinterpretada. Verificar el rango contra el spec Y una captura real antes de darle nombre semántico.
**Ver**: `internal/protocols/finsudp/wire/wire.go`, `.../realcap_test.go`, 3-10-2026.

## PITF-066: Barrer puntuacion Unicode en todo el repo: contar bien, y no romper codigo con la sustitucion
(En esta entrada el em-dash es U+2014 y el en-dash U+2013; se citan por codepoint, no por glifo, para no reintroducirlos.)
**Sintoma**: en la limpieza de rayas repo-wide (orden de Daniel, 3-10-2026), `git grep -P` con una clase que incluia U+2014 y U+2013 reporto **24.492** ocurrencias; el recuento real (script Python UTF-8) era **5.383**. Y un primer barrido con sustitucion uniforme rompio cosas: strings de UI donde la raya era un placeholder de "vacio" (p.ej. `operator || "<U+2014>"` quedo `": "`), comentarios godoc (`// Name <U+2014> desc` paso a `// Name: desc`, que viola la regla revive "comment should be of the form 'Name ...'") y comentarios que empezaban por raya (`// <U+2014> x` paso a `//: x`, que viola gocritic commentFormatting).
**Causa raiz**: dos trampas distintas. (1) `git grep` con una clase de caracteres multibyte cae a **modo byte**: la clase pasa a ser la clase de bytes {E2,80,93,94}, asi que matchea cualquier caracter que comparta esos bytes (la flecha U+2192, la ellipsis U+2026, y casi todo el bloque U+2000 a U+206F). El conteo estaba inflado ~4,5x. (2) La sustitucion correcta de la raya es **contextual**, y en codigo hay posiciones donde dos-puntos o coma rompen lint o cambian la salida: godoc (exige nombre + espacio), inicio de comentario, y glifo-placeholder dentro de un string.
**Regla**: para contar o sustituir un caracter Unicode en todo el repo, usar un **script Python UTF-8**, no `git grep` con clase de bytes. El separador se elige por **contexto LOCAL** (los pocos chars antes de la raya), no por toda la linea, para que el mismo literal mapee igual en el codigo y en su test (los tests de igualdad de strings siguen verdes). Reglas code-aware que funcionaron: rango tipo `v1.4-v1.11` pasa a guion corto; raya pegada a comilla o markup (placeholder) pasa a guion corto; raya al inicio de comentario o en godoc (nombre seguido de raya) pasa a un espacio; etiqueta en negrita seguida de raya pasa a dos-puntos; el resto pasa a coma. Excluir binarios (`.docx`, `.bin`: ahi los bytes no son puntuacion). Validar con build + suite + **ambos** linters (v2.11.4 y v2.14.0) con y sin `-tags offensive`, y `gofmt -w` (el barrido re-alinea comentarios trailing).
**Ver**: `scratchpad/dedash.py` (metodo), commit `4b09ca6` (740 ficheros, 0 rayas), 3-10-2026.

## PITF-067: Un parser reverse-engineered puede modelar el mensaje equivocado del protocolo
**Síntoma**: el fingerprint GE-SRTP enviaba una trama de 56 bytes con byte 0 = 0x02 como "connection init" y esperaba una respuesta con byte 0 = 0x03. Contra un PLC GE real eso es incorrecto: el handshake de inicialización real es enviar 56 bytes TODO ceros, y el PLC responde con byte 0 = 0x01. El 0x02/0x03 son los tipos del mensaje de OPERACIÓN (Transmit/Return), que van DESPUÉS del init. Resultado: el probe rechazaba la respuesta válida (0x01) de un dispositivo real, igual que PITF-064 (Modbus FC43) devolvía 0 objetos para dispositivos reales.
**Causa raíz**: el modelo del parser se reverse-engineered de las fuentes equivocadas (nmap NSE gesrtp-info y notas que describen el mensaje de operación), no del handshake de init, que el paper de exploit omite. Es el primo de PITF-064/065: allí el fixture fabricado validaba un layout equivocado; aquí el MODELO reverse-engineered describía el mensaje equivocado del protocolo. En ambos, solo el contraste con la realidad lo revela.
**Cómo se caza**: dos fuentes empíricas independientes convergen. (1) La implementación GE_SRTP de Collin Matthews (probada contra GE 90/30 y 90/70 reales, con Wireshark): `INIT_MSG = bytearray(56)` (56 ceros) y el comentario "first send 56 bytes of all 0s ... It will respond with 01 00 ..."; `BASE_MSG[0]=0x02` es "Transmit" (operación), 0x03 "Return". (2) La firma Shodan "general-electric-srtp" (automayt/ICS-pcap GE-SRTP/Notes.txt): respuesta de 56 bytes con byte 0 = 0x01, byte 8 = 0x0f.
**Fix**: `BuildConnectionInit` envía 56 ceros; `ClassifyResponse`/`IsMailboxResponse` aceptan byte 0 = 0x01; se añadió la constante `TypeInitResponse=0x01` y se mantuvieron `TypeRequest=0x02`/`TypeResponse=0x03` para la operación (Read Long Status y el proxy). `realcap_test.go` valida la respuesta init real byte a byte.
**Regla (extiende PITF-064/065)**: un parser o cliente reverse-engineered no está validado hasta contrastarlo con una implementación que funcione contra hardware real, O una captura real. Cuando el único aval sea reverse-engineering de terceros (nmap NSE, recog, un blog), buscar una SEGUNDA fuente independiente antes de confiar; y si el probe envía algo a la red, confirmar que el mensaje es el que el dispositivo real espera (hay protocolos, como GE-SRTP, con un paso de init que las fuentes públicas omiten).
**Ver**: `internal/protocols/gesrtp/wire/{wire.go,wire_test.go,realcap_test.go}`, `docs/protocols/gesrtp.md`, 3-10-2026.

## PITF-068: el "magic" 0xCDCDCDCD de CoDeSys era un artefacto de memoria no inicializada (reconocimiento CORREGIDO 2026-10-04; probe activo channel-open SHIPPED OPT-IN 2026-10-04 como codesys-active)
**Síntoma**: el fingerprint CoDeSys (`internal/protocols/codesys`) usaba `BlockDriverMagic = {0xCD,0xCD,0xCD,0xCD}` como prefijo de 4 bytes que ENVIABA (BuildHello) y RECONOCIA (Classify) en TCP/1217. Ninguna fuente respaldaba ese valor. Corregido al real `{0x00,0x01,0x17,0xE8}` el 4-10-2026 (ver Estado).
**Causa raíz / sospecha**: 0xCDCDCDCD es el patrón de relleno "uninitialised heap" del runtime de debug de MSVC. Es muy probable que durante el reverse-engineering alguien leyera un buffer sin inicializar y lo tomara por el magic. Mismo género que PITF-067 (GE-SRTP): un modelo reverse-engineered del dato equivocado.
**Evidencia del valor correcto (TRES fuentes independientes)**: la pila PDU de CODESYS abre con la Block Driver layer, header de 8 bytes (magic[4] + size[4]) y magic 0xE8170100 (little-endian). (1) PoC del gateway V3 de Tenable: `pack('<II', 0xe8170100, len+8)` al enviar y `if magic != 0xe8170100: raise 'Invalid magic'` al recibir (puerto 11743, DWRCS.exe). (2) Paper de Kaspersky ICS-CERT (Alexander Nochvay, "Security research: CODESYS Runtime"): la pila PDU empieza por la Block Driver layer; el runtime lee 8 bytes y compara los primeros 4 con la magic constant. Esa capa es la base común a toda la pila, incluido el Gateway (1217). (3) Captura real `cds3.pcapng` (descargada y re-parseada byte a byte el 3-10-2026 con `dumptcp.py`): sesión con un gateway CODESYS V3 en **TCP/11740**; TODAS las tramas, en ambos sentidos, empiezan por `00 01 17 e8` (= 0xe8170100 LE) seguido del tamaño LE (p.ej. `000117e8 54000000` = 84 B, el len real). Confirma magic + layout del header, y añade el puerto de gateway V3 observado (11740, no 1217/11743).
**Estado: reconocimiento CORREGIDO el 4-10-2026; probe activo AÚN APLAZADO.** La constante `BlockDriverMagic` pasó a `{0x00,0x01,0x17,0xE8}` (0xE8170100 LE), validada contra las TRES fuentes de arriba (captura real + referencia probada de Tenable, re-verificada en vivo esa fecha): `Classify`/`IsBlockDriverFrame` ya reconocen tramas reales, y los tests fixture-que-no-validaban-nada (alimentaban CD CD CD CD y comprobaban que se reconocía) se sustituyeron por tests con los bytes reales de la captura (`00 01 17 e8` + length LE). Lo que sigue aplazado es un probe que PROVOQUE respuesta: `BuildHello` solo envía el magic de 4 bytes, que no es una trama completa (el gateway espera magic + length + channel-open), así que un gateway real no responde. El channel-open del PoC de Tenable es independiente del host (sender/receiver a cero, client-id aleatorio, sin IP embebida) PERO está validado solo contra DWRCS.exe en 11743; la primera PDU cliente de la captura en 11740 sí incrusta una IP de endpoint (`c0a83872` = 192.168.56.114); no hay probe confirmado para el gateway canónico 1217. Construir y enviar uno cambia la postura activa de una herramienta pública. **Resuelto 4-10-2026 (decisión de Daniel: opt-in):** el channel-open se construye en `wire.BuildChannelOpen` (block driver + L3 datagram + L4 channel-open meta, direcciones a cero = independiente del host), porteado byte a byte del PoC de Tenable y validado contra esa referencia (`wire/channel_test.go`, client id fijo 0x11223344). Se envía SOLO desde el plugin opt-in `codesys-active` (DefaultPort 0 / OptIn), fuera del sweep por defecto, así que un escaneo normal sigue siendo banner + reconocimiento (postura read-only intacta). NO ejercitado contra un gateway 1217 vivo (frame-validado, no live-validado): la respuesta se clasifica por el magic ya confirmado. La ruta de banner (substrings CODESYS/3S) sigue siendo la señal del build por defecto. (Nota: la edición de wire.go que antes paró el clasificador de seguridad era la del probe activo; las ediciones de esta pasada -reconocimiento, BuildChannelOpen, plugin opt-in, tests, docs- no fueron paradas.)
**Regla**: un "magic" de 4 bytes igual a un patrón de relleno conocido (0xCDCDCDCD = MSVC uninit heap; también 0xDEADBEEF, 0xBAADF00D, 0xFEEEFEEE, repeticiones de un solo byte) es sospechoso por defecto: verificar contra una implementación o captura antes de confiar. Para arreglar el probe hace falta una captura del gateway 1217, o construir un PDU de sonda válido y confirmar que provoca respuesta.
**Ver**: `internal/protocols/codesys/wire/wire.go`, Tenable `poc/codesys/...tra_2020_04.py`, Kaspersky ICS-CERT CODESYS Runtime paper, captura `cds3.pcapng` (scratchpad, TCP/11740), 3-10-2026; reconocimiento corregido 4-10-2026.

## PITF-069: el fingerprint de ProConOS enviaba y esperaba el mensaje equivocado (corregido)
**Síntoma**: el fingerprint ProConOS (`internal/protocols/proconos`, TCP/20547) enviaba un hello de 16 bytes `01 06 00 10` + "PROCONOS" + ceros, y clasificaba la respuesta como ProConOS si los primeros 4 bytes echo-eaban ese prefijo (o contenía un banner). Contra un PLC ProConOS real es incorrecto en los dos lados.
**Causa raíz**: mismo patrón que PITF-067 (GE-SRTP). El modelo venía de "un dissector + un módulo metasploit" que no coincide con cómo se fingerprintea ProConOS en 20547. El propio package doc admitía que las fuentes "conflict" y eligió la variante equivocada.
**Valor correcto (dos fuentes independientes, byte a byte)**: (1) DigitalBond Redpoint `proconos-info.nse` (el escáner de facto de ProConOS): `req_info = bin.pack("H","cc01000b4002000047ee")`, valida que el primer byte de la respuesta es 0xcc, con campos en offsets 13/45/78 (Ladder Logic Runtime / PLC Type / Project Name). (2) Praetorian nerva `proconos`: `request := []byte{0xcc,0x01,0x00,0x0b,0x40,0x02,0x00,0x00,0x47,0xee}` y `ResponseSignature = 0xcc`, valida `response[0] != 0xcc`.
**Fix**: `BuildHello` envía la query de 10 bytes `cc 01 00 0b 40 02 00 00 47 ee`; `Classify`/`IsProConOSFrame` aceptan byte 0 = 0xcc (constante `ResponseSignature`), con los banner substrings como fallback de recall. Se eliminaron `ProConOSHelloPrefix` / `ProConOSToken` / `HelloLen`. Tests actualizados.
**Regla (extiende PITF-067)**: cuando un fingerprint propietario se apoya en "un dissector" o "un módulo metasploit" y el package doc admite que las fuentes están en conflicto, es bandera roja: buscar el escáner de facto del protocolo (Redpoint / nmap NSE) y una segunda implementación, y confirmar query + response signature antes de confiar. Un dissector de Wireshark describe el formato de las tramas, no necesariamente la sonda de fingerprint correcta.
**Ver**: `internal/protocols/proconos/wire/wire.go`, Redpoint `proconos-info.nse`, Praetorian nerva `proconos`, 3-10-2026.

## PITF-070: CVEs FABRICADAS y mal atribuidas en los comentarios base de cve_exposure
**Síntoma**: un barrido de las citas de CVE del repo (`grep -rhoE "CVE-[0-9]{4}-[0-9]+" --include=*.go`) destapó un CLÚSTER de SEIS CVEs FABRICADAS (IDs que NO existen en NVD), todas en comentarios que justifican el baseline `cve_exposure` de un protocolo:
- `CVE-2025-12345` (knxip, "tunnelling-frame parser"): la secuencia 12345 la delata.
- `CVE-2025-1432` (slmp, "undocumented diag service"): no existe.
- `CVE-2025-3047` (dlms, "COSEM action-method side-channel"): ese id real es de AWS SAM CLI, nada de DLMS.
- `CVE-2025-0712` (gesrtp, "Mark VIe DCS unauth firmware download"): no existe.
- `CVE-2025-7842` (mbustcp, "libmbus-rs heap overflow"): no existe.
- `CVE-2020-25822` (pbxhttp, "FreePBX RCE family"): la API REST de NVD devuelve `totalResults=0`. No es un patrón 2025, por eso sobrevivió al primer barrido; cayó al verificar id por id contra NVD (3-10-2026).
Más mis-atribuciones: `CVE-2021-22779` (la Modicon ModiPwn de Modbus) reutilizada como "KNX/IP backdoor" (knxip) y como "IEC 61850 auth bypass" (mms); y `CVE-2020-15782` (la de S7-1200/1500 que sí uso en la salida) puesta como "SIMATIC DLMS auth bypass" (dlms).
**Causa raíz**: los comentarios base se rellenaron con CVEs plausibles de memoria, incluidos placeholders inventados. La salida real de CVEs vive en `internal/cve` (`ForS7`/`ForENIP`/`ForPCWorx`/`ForFINS`), web-verificada registro a registro, así que ninguna fabricada llegó a un finding; pero una CVE inventada en un repo de seguridad es un problema de credibilidad por sí misma.
**Acción tomada (3-10-2026)**: eliminadas las cinco fabricadas. De-especificados (lista de ids sustituida por justificación cualitativa) los cinco comentarios contaminados: knxip, slmp, dlms, gesrtp, mbustcp, mms. Ya antes se habían reanclado a CVEs verificadas los de ENIP, pcworx, finsudp y modbus (que tenían mis-atribuciones: CVE-2017-7898 "open ports", CVE-2020-12029 "ENIP DoS", CVE-2018-19009 que es de Pilz; CVE-2020-9436 que es de TC ROUTER; CVE-2017-9853 que es de SMA Solar; CVE-2015-1015 que no existe).
**Auditoría de los 13 sospechosos (3-10-2026, decisión de Daniel "verificar uno a uno")**: los 13 comentarios base restantes (hartip, iec104, dnp3, bacnet, opcua, sip, s7, twincat, iax2, fox, cwmp, atg, pbxhttp) se verificaron id por id contra la API REST de NVD (`services.nvd.nist.gov/rest/json/cves/2.0?cveId=…`). La tasa de error se confirmó alta: de 13, solo 4 estaban limpios de origen.
- **Fabricada (no existe en NVD)**: CVE-2020-25822 (pbxhttp) → arriba, string eliminado del código.
- **Reales pero MAL ATRIBUIDAS, de-especificadas (lista sustituida por justificación cualitativa, el id real se nombra en el comentario con su producto correcto)**: iec104 (CVE-2017-12089 es un DoS de Rockwell MicroLogix 1400; CVE-2019-13548 es el web-server de CODESYS V3, ninguno IEC-104); bacnet (CVE-2018-10628 es AVEVA InTouch; CVE-2020-12511 es un CSRF de Pepperl+Fuchs IO-Link, ninguno BACnet; se mantiene CVE-2019-12480, DoS real del BACnet Protocol Stack); sip (CVE-2017-3881 es el Cisco IOS Smart Install RCE, no SIP); opcua (CVE-2019-10936 es un DoS de PROFINET de Siemens, no open62541; se mantienen CVE-2017-12069 XXE y CVE-2022-29862); fox (CVE-2015-2916 es un CSRF de Securifi Almond, no Niagara; se mantienen CVE-2012-3024 y CVE-2017-16744); iax2 (CVE-2007-3764 es el chan_skinny de Asterisk, no IAX2; se mantiene CVE-2008-3263, POKE flood real de IAX2); atg (CVE-2017-14432/14433 son del Moxa EDR-810, CVE-2018-5443 es Advantech WebAccess, ninguno Veeder-Root; se cita cualitativamente el aviso real 2025 TLS4B, CISA ICSA-25-296-03 / CVE-2025-58428).
- **Sin ningún id verificable, de-especificadas por completo**: hartip, twincat.
- **Limpias de origen, verificadas y mantenidas con su atribución correcta**: s7 (CVE-2014-2249 CSRF S7-1500, CVE-2018-13815 DoS S7-1200/1500); dnp3 (CVE-2013-2825 Elecsys, CVE-2013-2829 MatrikonOPC, CVE-2014-5410 Rockwell); cwmp (CVE-2014-9222 Misfortune Cookie / RomPager); y las partes mantenidas de bacnet/opcua/fox/iax2/pbxhttp de arriba. pbxhttp mantiene además CVE-2014-7235 (ARI RCE), CVE-2019-19006 (auth bypass, CISA KEV) y CVE-2024-41713 (Mitel MiCollab, CISA KEV).
**Lección**: el patrón de placeholder (12345/CVE-2025) solo caza las groseras. La de-atribución y el id-inexistente-pero-plausible (CVE-2020-25822) solo caen verificando cada id contra NVD. La verificación por buscador web NO basta: el resumidor del buscador dio "no encontrado" para ids que SÍ existían y "existe" para atribuciones falsas; la API REST de NVD es la fuente autoritativa (`totalResults` + `descriptions[0].value` dan existencia y producto).
**Regla**: ningún CVE id se escribe de memoria, ni en un comentario de justificación. Se verifica contra la **API REST de NVD** (`services.nvd.nist.gov/rest/json/cves/2.0?cveId=…`: `totalResults` da existencia, `descriptions[0].value` da producto), que es la fuente autoritativa; el buscador web NO basta (miente en ambos sentidos). Si no se puede verificar existencia + producto, la justificación se deja cualitativa (sin id). Una secuencia tipo 12345/0000/1111 es casi siempre placeholder. Ningún id FALSO (inexistente) se deja como string en el código ni siquiera marcado como "removed" (un grep de CVEs debe devolver solo ids reales); un id REAL pero mal atribuido sí puede quedar en el comentario si se nombra su producto correcto. El registro exacto de los falsos vive aquí.
**Hardening posterior (4-10-2026, "cve_exposure hardening")**: de las seis familias de-especificadas, dos SÍ tenían CVEs reales de dispositivo verificables en NVD y se re-poblaron en `internal/cve` (keyed por identidad, como ForFINS, no baseline cualitativo):
- **gesrtp** → `ForGESRTP(modelHint)`: por **modelo de CPU** y por CVE, según lo que nombra cada aviso en NVD: RX3i CPE305/310/330/400 y CRU320 → CVE-2018-8867 (7.5, input validation) + CVE-2019-13524 (7.5, halt-mode DoS); RX3i CPE100/115/302/410 → solo 13524; RSTi-EP CPE100 y RXi CPU320 → solo 8867. NO se atribuyen: pistas de familia ("PACSystems", "PACSystems_RX3i"), RX7i, CPUs RX3i que ningún aviso lista (CPU310, CPL410), Series 90 ni VersaMax. **Corregido en la auditoría del 7-10-2026**: la primera versión (4-10) atribuía por familia ("PACSystems"/"RX3i"/"IC695") y daba los CVE del RX3i a un RX7i (el extractor corta "PACSystems RX7i" en "PACSystems"), y a CPL410/CPU310.
- **slmp** → `ForSLMP(model)`: iQ-F/FX5 → CVE-2025-7731 (7.5, SLMP en claro, intercepción de credenciales) + CVE-2024-8403 (7.5, FX5-ENET DoS); iQ-R ("R"+dígito) → CVE-2020-5668 (7.5, DoS). Q/L/FX legacy → nil.

Las otras tres NO tienen match seguro y se dejaron en baseline cualitativo, con el comentario corregido a la realidad NVD:
- **dlms**: NVD indexa CERO CVEs de dispositivo bajo DLMS/COSEM a nivel protocolo (solo un bug del disector de Wireshark). La afirmación "deepest CVE catalogue" y el baseline 12 (el más alto) NO estaban respaldados: **corregido a 6**.
- **knxip**: 41 CVEs reales pero vendor-producto (Schneider spaceLYnk/Wiser/U.motion, ETS, ise), no de KNXnet/IP genérico; sin identidad de vendor no se pueden atribuir sin mis-atribución. Baseline 11 se mantiene (hay flujo real), comentario afinado a vendors verificados.
- **mbustcp**: los CVEs reales de "M-Bus" son wireless M-Bus (otro transporte) o del interfaz web del gateway PiiGAB 900S (no atribuible desde una trama M-Bus/TCP). Baseline 6 se mantiene, comentario precisado.
Verificación: barrido NVD REST API por familia (keywordSearch + descripción), one-by-one.
**Ver**: knxip/slmp/dlms/gesrtp/mbustcp/mms `*.go` (primer barrido); iec104/bacnet/opcua/sip/fox/iax2/atg/pbxhttp/hartip/twincat `*.go` (auditoría de los 13); s7/dnp3/cwmp `*.go` (verificados limpios); `internal/cve` (salida verificada, +ForGESRTP/ForSLMP el 4-10); 3-10-2026 / 4-10-2026.

## PITF-071: firma compartida entre petición y respuesta = falso positivo ante un servicio que refleja (eco)
**Síntoma**: auditoría del 7-10-2026. `codesys`, `codesys-active` y `proconos` daban "confirmado" (capability 70/60, severidad alta) contra un servidor de eco local, con el binario real (`fingerprint probe` a 127.0.0.1).
**Causa raíz**: el clasificador mira una firma que también lleva la PETICIÓN. CoDeSys: toda trama del Block Driver abre con el mismo magic `00 01 17 e8` en ambos sentidos. ProConOS: la petición es `cc01…` y la respuesta se reconoce por `buf[0]==0xcc`. Un servicio que refleja (echo, tarpit, algunos honeypots) devuelve nuestra propia sonda y pasa la firma. Peor: el test `TestProbeSignature` de proconos usaba como "respuesta real" los bytes de la PETICIÓN, una fixture-eco que validaba el error (mismo género que la fixture sintética de PITF-064/067).
**Fix**: el plugin rechaza, antes de clasificar, una respuesta que sea prefijo de lo enviado (`netutil.IsEcho(sent, reply)`, helper compartido; cubre también un eco cortado por una frontera de lectura TCP). Una respuesta real lleva su propio length/PDU y nunca es prefijo de la sonda. Tests de eco completo y parcial. La fixture de proconos se cambió por la respuesta real de la captura (`cc00…`). NO se añadió "byte1 == 0x00" a ProConOS: hay una sola captura y sería generalizar de un caso.
**Barrido de eco en los 35 plugins (7-10-2026, método diferencial: capability contra eco vs contra un servidor mudo, TCP+UDP)**: arreglados `codesys`, `codesys-active`, `proconos`. Los 7 anteriores que el barrido destapó se arreglaron la misma noche (7-10-2026, trabajo autónomo pedido por Daniel): `atg`, `dlms`, `dnp3`, `iax2`, `iec104` con el check de eco compartido `netutil.IsEcho`; `opcua` con una regla de protocolo (HEL es solo de cliente: un HEL de vuelta es un reflejo, antes caía en la rama `default` y contaba como UA); `pcworx` resultó tener la causa raíz en la PETICIÓN (no era la del protocolo real), ver PITF-072. `modbus`: sin comprobar (fija capability 60 siempre; el método no discrimina). `atmodem`, `cwmp`, `mqtt`, `opcuahttps`, `pbxhttp`: error, no finding (no es falso positivo). El resto, limpio; `melsoft` (0x57→0xD7) y `slmp` (0x50→0xD0) inmunes por diseño.
**Regla**: si el campo que identifica la RESPUESTA puede aparecer en la PETICIÓN, el plugin debe rechazar el eco. Al validar un parser, probarlo también contra un servidor de eco (script del barrido: /tmp/echo_sweep.py de la sesión; rehacer si hace falta: dos servidores TCP+UDP, eco y mudo, y comparar capability). Una fixture que es la propia petición no es una respuesta.
**Ver**: `internal/netutil/echo.go` (`IsEcho`), los `Probe` de codesys/codesys-active/proconos/atg/dlms/dnp3/iax2/iec104, `opcua.classifyFrame` (HEL), tests `*Echo*` (cada uno comprobado por mutación: falla sin el arreglo); 7-10-2026.

## PITF-072: PC Worx enviaba un hello inventado y aceptaba su propio prefijo como respuesta
**Síntoma**: el barrido de eco del 7-10-2026 (PITF-071) daba `pcworx` como confirmado contra un servidor de eco. Al buscar la causa: el `Classify` tenía una rama literalmente llamada `"PCWorx prefix echo"` que aceptaba una respuesta que empezase por los 4 bytes de NUESTRA petición (`01 01 00 1C`).
**Causa raíz**: el hello era un modelo inventado: 32 bytes `01 01 00 1C` + `IBETH01\0` + 20 ceros, documentado como "sacado del NSE `pcworx-info` y de Conpot" y con la promesa de que "todo PLC acepta este hello y responde con el banner". Ninguna de las dos cosas era cierta. El NSE real (`init_comms`) envía 26 bytes `01 01 00 1a 00 00 00 00 78 80 00 03 00 0c "IBETH01N0_M" 00`, y un PLC real responde `81 01 00 14 …` (20 bytes, SIN banner); el modelo solo llega en una respuesta posterior de servicio `0x06`. Resultado: contra un PLC real el plugin daba NEGATIVO (ni prefijo ni banner en la primera respuesta) y contra un eco daba POSITIVO. Estaba al revés. El realcap anterior solo validaba `Classify` sobre la respuesta `0x06` (que sí trae banner), nunca que nuestro hello provocase respuesta: mismo género que PITF-069 (ProConOS enviaba bytes inventados).
**Evidencia (tres fuentes que coinciden byte a byte)**: (1) `pcworx-info.nse` de DigitalBond/nmap: su `init_comms` y su regla "si la respuesta empieza por 0x81, seguimos". (2) Captura real de un ILC 151 ETH (hi-KK/ICS-Protocol-identify `PCWorx协议识别.pcapng`): la primera petición del cliente es idéntica al `init_comms` y la respuesta es `81 01 00 14 …`. (3) Captura real de un ILC 191 ETH 2TX (reidmefirst/PC-PCAP, Dragos): toda respuesta empieza por `0x81`. En las dos capturas, las 25 respuestas `0x81` llevan su propia longitud total big-endian en los bytes 2..3, sin una excepción.
**Fix (7-10-2026)**: `BuildHello` = el `init_comms` del NSE. `Classify`/`IsPCWorxFrame` reconocen la trama de respuesta (byte 0 `0x81`, longitud big-endian plausible en 2..3; no se exige igualdad exacta para tolerar segmentación TCP); el banner queda como respaldo (ninguna subcadena aparece en la petición). Fuera la rama "prefix echo". `netutil.IsEcho` en el probe como defensa en profundidad. Tests: la petición coincide con la captura, las 3 respuestas reales se reconocen, un buffer con forma de petición NO, y eco → negativo. Los dos tests que fijaban "prefijo propio = positivo" se reescribieron.
**Regla**: un realcap que solo valida el clasificador sobre UNA respuesta no valida el probe. Hay que comprobar también que la petición que enviamos es la del protocolo real (contra NSE/captura) y que la PRIMERA respuesta a esa petición clasifica. Una rama de clasificador cuyo nombre dice "echo" es una alarma.
**Ver**: `internal/protocols/pcworx/wire/{wire,wire_test,realcap_test}.go`, `internal/protocols/pcworx/{pcworx,pcworx_test}.go`, `docs/protocols/pcworx.md`, `docs/parser-validation.md`; 7-10-2026.

## Template para nueva entrada
Ver `.context/templates/pitfall.md`.
