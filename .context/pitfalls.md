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
**Síntoma**: `make ci` local omite jobs que el CI remoto sí corre (builds -tags offensive/sqlite, fuzz, go-licenses) → bitrot no detectado hasta el push.
**Regla**: `make ci` es superset funcional de los jobs del CI que detectan bitrot (todas las variantes de build + tests + seguridad completa).
**Implementación correcta**: target `ci: lint build build-offensive build-sqlite test-race test-cover test-fuzz sec context-check`. `make sec` incluye `go-licenses check` además de gosec/govulncheck/trivy/gitleaks. Documentar en CONTRIBUTING que `make ci` es aproximación local (el remoto es autoritativo) y aun así cubre el mismo espacio.

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

## Template para nueva entrada
Ver `.context/templates/pitfall.md`.
