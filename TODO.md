# ElSereno Roadmap

## Phase 0 — Scaffolding
- [ ] Estructura de repo sección 6
- [ ] go.mod con path + toolchain exacta preguntados
- [ ] cmd/elsereno/main.go con signal.NotifyContext + exit 128+signum + cobra (F0 funcionales + stubs)
- [ ] internal/core con interfaces + entidades + value types + errors (sentinels en paquete emisor)
- [ ] internal/bus con findings CopyFrom + audit sequential single-thread + métricas
- [ ] internal/config con Koanf + validator + unknown-fields rejector + ErrUnknownConfigField
- [ ] internal/db con pool pgx + goose + migración 00001 completa (incluye web_state, outbox_dead, audit event_type enum, ON DELETE RESTRICT en audit_purge_markers)
- [ ] internal/audit con genesis + tombstone purge + rebase compact (excluye metadata event_types) + JCS canonical fields + ErrChainBroken aquí
- [ ] internal/render SafeBytes
- [ ] internal/telemetry zerolog stderr + redaction hook específica + UUID exclusion + prometheus low-cardinality + label sanitizer + otel
- [ ] internal/scoring interfaces + YAMLs defaults
- [ ] internal/web http.Server full timeouts + bearer + cookie+token_generation(persisted en web_state + cache TTL 5s en middleware web) + CSRF(HKDF vault) + CSP + headers + rate-limit per-IP(loopback exento)+per-token + body limit + healthz/readyz(tail verify)
- [ ] internal/scope opcional + AUP + CIDR v4/v6 + binds.allow
- [ ] internal/creds vault AES-GCM+Argon2id + HKDF Derive + unlock-once + memguard + init/unlock/lock/status + creds show --reveal audited + env-TTY warning (ADR-026)
- [ ] internal/doctor runtime+PG+TLS+nmap+CAP_NET_RAW/root+DNS+IDN+creds+NTP+disk+IPv6+mlock+vault status
- [ ] internal/wizard huh
- [ ] internal/exec SafeCommand con CommandSpec{Name,Flags,Positional} + path allowlist + `--` determinista
- [ ] cmd plugins.go + plugins_offensive.go
- [ ] Token rotation con advisory lock + UPDATE RETURNING + fichero 0600 + audit
- [ ] .env.example alineado con docker-compose trust auth
- [ ] .golangci.yml con lista completa de linters (sección 11)
- [ ] .goreleaser.yml (default CGO=0 cross; sqlite CGO=1 nativo)
- [ ] CI ci.yml PRs reducido + push/tags full + build-offensive + build-sqlite nativo + dep-review condicional
- [ ] CI release.yml + nightly.yml + codeql.yml
- [ ] Makefile completo (ci incluye build variantes + test-fuzz + sec con go-licenses)
- [ ] Dockerfile pin exacto + Dockerfile.sqlite CGO
- [ ] docker-compose.dev.yml Postgres 16 trust + bind 127.0.0.1:5433 explícito + Adminer
- [ ] .devcontainer
- [ ] lefthook con DCO sign-off + golangci-lint --new-from-rev=HEAD~1
- [ ] .gitignore con .elsereno/
- [ ] .editorconfig + .gitleaks.toml
- [ ] Documentación raíz (README con target acquisition secure, SECURITY, LEGAL con GDPR, CONTRIBUTING con 5 ficheros de reading order, CODE_OF_CONDUCT, NON-GOALS, CHANGELOG)
- [ ] .context/ completo (INDEX, STATE, _quickref, conventions, architecture, glossary, scoring, persistence, web, testing-strategy, security-model, pitfalls con PITF-001..036, decisions 001-026, protocols placeholders, templates protocol+adr+snapshot+pitfall, snapshots, CHANGELOG)
- [ ] TODO.md inline
- [ ] scripts/context-check.sh (valida pitfalls ≥36 + detector PITF-007 sobre docs del repo con exclusión de code fences y pitfalls.md)
- [ ] scripts/gen-manpages.sh (cobra man1 + pandoc man5/7)
- [ ] scripts/install-hooks.sh
- [ ] scripts/run-fuzz.sh
- [ ] man/src/man5/ y man/src/man7/ con fuentes Markdown (elsereno.yaml.5, elsereno-scope.5, elsereno-scoring.5, elsereno-protocols.7 esqueleto, elsereno-security.7)
- [ ] completions/ cobra
- [ ] doc.go en cada paquete

## Phase 1 — Inputs, scanner, scoring, triage, observability
- [ ] Inputs Shodan/Censys/nmapxml/list/stdin con mocks
- [ ] Scanner async con resolve A+AAAA+IDN+dedupe + rate limits + jitter + retries + circuit breaker + resume snapshots + dedup temporal
- [ ] Scoring engine v1 con weights ADR-006
- [ ] triage grouping quick-wins/strategic
- [ ] explain / why / lint / fmt
- [ ] Outputs NDJSON/CSV/HTML mínimo
- [ ] Progress bars ETA + NO_COLOR
- [ ] Prometheus pobladas + label sanitizer activo
- [ ] Retention keep-if-referenced
- [ ] Outbox con retry+backoff+dead-letter
- [ ] Tests IPv6 integración

## Phase 2 — XOT + AT modems
### 2a XOT
- [ ] Parser XOT RFC 1613
- [ ] Fingerprint CALL REQUEST/CLEAR
- [ ] REPL call/clear/data + PAD X.29
- [ ] Proxy pass-through render seguro
- [ ] Simulador simulators/xot/
- [ ] Fuzz + corpus malicioso
- [ ] Golden files
- [ ] ADR XOT
### 2b atmodem
- [ ] Parser AT líneas+multilinea
- [ ] Fingerprint Hayes+GSM+vendor+ascensor EN 81-28
- [ ] Read-only info/config/network/signal/imsi/imei + audit entry por op
- [ ] REPL AT con history+tab-completion
- [ ] Proxy bloqueo ATD*/ATA/AT+CMGS/CMGW/CMSS/CMGD/CFUN/CPWROFF/+++
- [ ] Simulador simulators/atmodem/
- [ ] Fuzz + corpus malicioso
- [ ] ADR atmodem

## Phase 3 — Proxy + Modbus
- [ ] Framework proxy TCP/UDP con hooks
- [ ] Plugin Modbus read + REPL
- [ ] Suite adversarial FC escritura
- [ ] Chaos helper test/chaos/
- [ ] Simulador pymodbus

## Phase 4 — Resto ICS + Dashboard
- [ ] Plugins S7/ENIP/BACnet/DNP3/IEC-104/HART-IP/Fox/ATG/banner+dict
- [ ] Conpot en docker-compose.test.yml
- [ ] Dashboard overview/findings/triage/runs/scope/protocols
- [ ] SSE live scans
- [ ] TUI bubbletea
- [ ] API /api/v1 + OpenAPI

## Phase 5 — Offensive (build tag)
- [ ] Writes Modbus/S7/CIP/BACnet triple confirm
- [ ] Exploits arch + 2 CVE
- [ ] Harvest Telnet/FTP/HTTP-Basic/SNMPv1-2c → vault
- [ ] Dial individual + blacklist ≤3 dígitos + configurable
- [ ] Sandbox seccomp Linux (verificar lib + ADR suplementario)
- [ ] --no-allowlist
- [ ] Canary scope.yaml

## Phase 6 — Reporting + release
- [ ] HTML pulido
- [ ] CEF/Syslog/JIRA/GitHub Issues
- [ ] OpenAPI autogenerada
- [ ] Webhooks outbox
- [ ] Dashboard pulido + vault UI
- [ ] docs/protocols/*
- [ ] Release 0.1.0 firmada
- [ ] Repo público

## Phase 7 — Hardening + 1.0
- [ ] Fuzz exhaustivo nightly
- [ ] Gremlins mutation
- [ ] STRIDE por módulo
- [ ] Pentest dashboard
- [ ] Supply chain audit
- [ ] OTel tracing production
- [ ] Backup automation cifrado
- [ ] Regresión benchmarks CI
- [ ] Release 1.0.0

## vNext
- [ ] L2 PROFINET DCP/GOOSE/SV con gopacket
- [ ] OPC UA/CoDeSys/Omron FINS/MELSEC SLMP/PCWorx/ProConOS/Crimson/GE-SRTP/IEC 61850 MMS/KNX/M-Bus
- [ ] Windows support
- [ ] Multi-user OIDC + roles
- [ ] Record & replay sesiones
- [ ] MITM transparente con routing
- [ ] ONYPHE/Fofa/Zoomeye/Shodan InternetDB inputs
- [ ] STIX 2.1 export
- [ ] Wardialing batch con scope file
