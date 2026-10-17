---
phase: F7
status: canonical
last-updated: 2026-04-20
token-budget: 1200
surface: web
---

# Threat model, web server + API + dashboard

Covers `internal/web/` (server, handlers, middleware, static,
templates, openapi). The web surface is the one external component
that accepts inbound HTTP; every byte entering this layer comes from
the operator's browser or an API client, but the server lives
loopback-only by default.

## Scope

| In scope | Out of scope |
|----------|--------------|
| `127.0.0.1:8787` HTTP endpoints | Non-loopback binds (require explicit TLS + `--i-know-what-im-doing`) |
| Dashboard HTML rendering | Upstream reverse-proxy TLS termination |
| `/api/v1/*` JSON + OpenAPI serving | Bearer token rotation (ADR-014) |
| Cross-site requests and DNS rebinding (browser guard) | Browser-side XSS defence beyond CSP |

## S, Spoofing

| Threat | Mitigation | Code |
|--------|------------|------|
| Attacker on same machine issues requests to the serve process | **Gap** in dev mode (loopback, no OIDC): no authentication. With OIDC, the routes with a role need a Bearer JWT; `/`, `/admin/security`, `/metrics`, `/healthz`, `/readyz` and `GET /api/v1/{plugins,scoring,health,health/pool,openapi.yaml}` stay open. No cookie, no token rotation (PITF-087) | `internal/web/handlers/api.go:wrapWithRole`, `cmd/elsereno/cmd_serve.go` |
| CSRF from malicious page in the same browser | Browser guard: writes from another origin (`Origin`, `Sec-Fetch-Site`) refused, write bodies or Content-Types other than JSON/NDJSON refused (everything a page can send without a CORS preflight); DNS rebinding refused by pinning `Host` to loopback names on a loopback bind. No CSRF token (PITF-092) | `internal/web/browserguard.go` |
| Forged OpenAPI spec distributed as "authoritative" | Spec served from the same binary + in-code declaration (`internal/web/openapi.Spec`). Tag artefacts include `cosign`-signed `docs/openapi.yaml` snapshot | `internal/web/openapi/spec.go` |

## T, Tampering

| Threat | Mitigation | Code |
|--------|------------|------|
| Attacker injects a template-rendered field with `<script>` | `html/template` auto-escapes; raw output blocked at compile time | `internal/web/handlers/dashboard.go` |
| Mutating request flows through without CSRF | The browser guard wraps every route; the API needs a Bearer only with OIDC (dev mode has no auth) | `internal/web/browserguard.go`, `internal/web/handlers/api.go:wrapWithRole` |
| Request body exceeds server limits | `http.Server` full timeouts (ReadHeaderTimeout, ReadTimeout, WriteTimeout, IdleTimeout, MaxHeaderBytes) | `internal/web/server.go:51` |

## R, Repudiation

| Threat | Mitigation | Code |
|--------|------------|------|
| Operator claims they didn't view a given finding | Access logs via zerolog include request ID + route + status + latency; SafeField on string fields | `internal/telemetry/logger.go` |
| Disputed token rotation | `token_rotate` event emitted to audit chain | `internal/audit/events.go` |

## I, Information disclosure

| Threat | Mitigation | Code |
|--------|------------|------|
| Server error leaks stack trace | Handlers return typed `http.Error` bodies without wrapped internal detail; zerolog logs the stack but redaction hook masks secrets | `internal/web/handlers/api.go` + telemetry hook |
| Dashboard leaks vault contents in a future panel | Vault UI not implemented in default build; operator flow requires TTY prompt. Placeholder in F7 chunk 7 adds a self-audit panel with no secret values | `internal/web/handlers/dashboard.go` |
| XSS via target-controlled banner in HTML report | `internal/render.SafeBytes` + `html/template` auto-escape; the HTML report writer's template only ever embeds sanitised strings | `internal/outputs/html/writer.go` |
| Cross-origin read of `/api/v1/openapi.yaml` | Endpoint is read-only; no CORS header set (default same-origin) | `internal/web/handlers/api.go` |

## D, Denial of service

| Threat | Mitigation | Code |
|--------|------------|------|
| Slowloris / slow-header attack | Full `http.Server` timeouts set in F1 chunk 3a | `internal/web/server.go` |
| Per-IP flood | Rate limiter 100 req/min per IP (loopback exempt) | `internal/web/middleware/rate.go` |
| Per-token flood | 300 req/min per Bearer token | `internal/web/middleware/rate.go` |
| Session table growth | `web_state` is a singleton row; token generation bumps an integer, not a row count | migration 00001 |

## E, Elevation of privilege

| Threat | Mitigation | Code |
|--------|------------|------|
| Non-loopback bind without TLS | `runServe` refuses unless `--tls-cert`, `--tls-key`, `--i-know-what-im-doing` all set | `cmd/elsereno/cmd_serve.go` |
| Dashboard path traversal | Handlers only serve in-code HTML + embedded static; no file-system routing | `internal/web/server.go` |
| CSRF bypass via stale token after rotation | n/a today: there is no CSRF token and no token rotation (PITF-087) | ADR-014 |

## Residual risk (accepted)

- **Single-operator auth model**: the dashboard has one Bearer token;
  no multi-user RBAC. Vnext ticket for OIDC / roles (section 15 of
  the brief).
- **No real-time SSE yet**: dashboard relies on 30 s meta-refresh;
  operator-visible stale data window accepted until F7+ delivers
  `/api/v1/stream`.
- **Loopback-default posture**: operators who must bind externally
  take responsibility for the TLS cert hygiene; project only
  validates flag presence, not cert chain trust.
