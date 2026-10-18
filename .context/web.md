---
phase: any
status: canonical
last-updated: 2026-04-19
token-budget: 1800
---

# Web server

## Server
`http.Server` with full timeouts (all configurable):

| Setting | Default |
|---------|--------:|
| `read_header_timeout` | 5 s |
| `read_timeout`        | 30 s |
| `write_timeout`       | 30 s |
| `idle_timeout`        | 120 s |
| `MaxHeaderBytes`      | 16 KiB |
| `max_body_bytes`      | 1 MiB |

## Binding
Default `127.0.0.1:8787`. Binding outside loopback requires: `--tls-cert`
+ `--tls-key` + `--i-know-what-im-doing`, and an audit `serve_start` entry.
`binds.allow` in `scope.yaml` restricts the serve bind when `--scope` is passed (PITF-098); `canary` is parsed but not applied.

## Auth (as built; ADR-014 described a different design)

- **Dev mode (default)**: when `auth.oidc` is not fully configured, the
  API has no authentication; the operator identity comes from the
  optional, spoofable `X-Operator` header. `serve` allows this only on a
  loopback bind (`validateBindSecurity`, `cmd/elsereno/cmd_serve.go`).
- **OIDC**: with `auth.oidc` (issuer, audience, JWKS URL) the routes
  that carry a role (`wrapWithRole`, `internal/web/handlers/api.go`)
  require a Bearer JWT validated against the JWKS: 401 without or with a
  bad token, 403 with too low a role. Required for any non-loopback
  bind. Even then `/`, `/admin/security`, `/metrics`, `/healthz`, `/readyz` and `GET /api/v1/{plugins,scoring,health,health/pool,openapi.yaml}` are served without a token.
- **Not built** (described here until 2026-10-16, PITF-087): the
  `~/.elsereno/web-token` file with `web.token_ttl_days` (the config key
  exists, nothing reads it), `token rotate` (a stub), the persisted
  `web_state.token_generation` and its cache, the `POST /login` cookie,
  and CSRF via `gorilla/csrf` (not a dependency). The CSRF key is still
  derived from the vault master (`info="elsereno/csrf/v1"`, ADR-017) and
  nothing reads it.
- **Browser guard** (17-10-2026, PITF-092; `internal/web/browserguard.go`):
  on a loopback bind a non-loopback `Host` gets 421 (DNS rebinding);
  writes (not GET/HEAD/OPTIONS) from another origin (`Origin`,
  `Sec-Fetch-Site`) get 403; writes whose body or `Content-Type` is not
  JSON or NDJSON get 415 (a bodyless write carries no `Content-Type`, or one of those two). It is not authentication:
  in dev mode any local process can still call the API. Before it, any
  page in the operator's browser could send requests to a loopback
  `serve`.

## Headers
- HSTS (only when TLS).
- `X-Frame-Options: DENY`.
- `X-Content-Type-Options: nosniff`.
- `Referrer-Policy: no-referrer`.
- Restrictive `Permissions-Policy`.
- CSP with **per-request nonces**.

## Rate limiting (wired 2026-10-18, PITF-100)
- `internal/web/middleware/ratelimit.go`, wrapped by `NewServer` inside
  `securityHeaders` and before `browserGuard`; `cmd_serve` passes the caps.
- Per-IP `rate_limit_per_min_ip = 100` (loopback exempt; RemoteAddr only,
  `X-Forwarded-For` ignored; IPv6 keyed by /64).
- Per-token `rate_limit_per_min_token = 300`, keyed by Bearer or, in dev
  mode, `X-Operator`; applies on loopback too.
- IP bucket checked first (a caller over its IP cap never creates a token
  bucket), then the token bucket; a token reserved from the IP bucket is
  handed back if the token bucket refuses. Either refusal: 429 +
  `Retry-After: 60`.
- Token keys stored as SHA-256; each map capped at 100 000 keys (full map:
  a key not in it passes without that limit, so nobody can fill it and
  lock out operators; the token is unverified, so the token cap only slows
  one runaway token); idle buckets swept once a minute, not per request.
- `/healthz`, `/readyz` never limited; 0 disables a dimension.

## Endpoints (F4 close)
- `GET /healthz`: liveness.
- `GET /readyz`: DB ping + migrations status + disk check + audit chain
  tail verification (`readyz.audit_tail_entries = 100`). Degraded
  without DB wiring; returns 200 with `"db":"skipped"`.
- `GET /metrics`: Prometheus (wiring lands with the findings sink).
- `POST /login`, `POST /logout`: planned, not built.
- `GET /`: dashboard overview page (inline HTML listing 12
  registered plugins). HTMX + Alpine move in for chunk 2 polish.
- `GET /api/v1/plugins`: plugin list (read-only).
- `GET /api/v1/scoring`: ADR-006 weights + severity thresholds.
- `GET /api/v1/health`: API-level health.

All `/api/v1/*` responses carry `{"schema":"api:v1","data":…}`. The
contract lives in `docs/openapi.yaml` (OpenAPI 3.1). Auth is as in the
Auth section above (dev mode, or OIDC on the routes with a role).

## Cookie flags
Not built: `serve` sets no cookie (PITF-087). The design was
`HttpOnly`, `SameSite=Strict`, and `Secure=true` only under TLS.

## Other
- Request ID propagated; OTel-compatible `traceparent`.
- Panic recovery per handler.
- Access log goes to stderr, separate from the application log.
