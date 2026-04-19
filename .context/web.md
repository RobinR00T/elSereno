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
+ `--tls-key` + `--i-know-what-im-doing` + the target address being listed
in `binds.allow` in `scope.yaml`, and an audit `serve_start` entry.

## Auth (ADR-014)
Dual:

- **`/api/v1/*`** — `Authorization: Bearer <token>`. Token is 32 bytes from
  `crypto/rand`, base64url-encoded, stored at `~/.elsereno/web-token`
  (0600). TTL per `web.token_ttl_days` (default 30). **No CSRF.**
- **`/` (HTML)** — `POST /login` exchanges Bearer for a cookie
  `HttpOnly, SameSite=Strict, Secure=<tls>`. Cookie embeds the current
  `token_generation`. CSRF via `gorilla/csrf`, key HKDF-SHA256 derived from
  the vault master key (`info="elsereno/csrf/v1"` — ADR-017).

### Token generation
Persisted in `web_state` (ADR-014, PITF-001). `token rotate` is a
transaction with `pg_advisory_xact_lock(hashtext('web_state_token_rotate'))`
+ `UPDATE ... RETURNING`; a fresh 32 B token is written to the 0600 file.

### Cache
Middleware caches `token_generation` with TTL
`web.token_generation_cache_ttl` (default 5 s — PITF-034). After a
rotation, cookies expire within that TTL.

## Headers
- HSTS (only when TLS).
- `X-Frame-Options: DENY`.
- `X-Content-Type-Options: nosniff`.
- `Referrer-Policy: no-referrer`.
- Restrictive `Permissions-Policy`.
- CSP with **per-request nonces**.

## Rate limiting
- Per-IP `rate_limit_per_min_ip = 100` (loopback exempt).
- Per-token `rate_limit_per_min_token = 300`.
- More restrictive limit wins.

## Endpoints (F0)
- `GET /healthz` — liveness.
- `GET /readyz` — DB ping + migrations status + disk check + audit chain
  tail verification (`readyz.audit_tail_entries = 100`).
- `GET /metrics` — Prometheus.
- `POST /login`, `POST /logout`.
- `GET /` — authenticated placeholder.
- `*` under `/api/v1/` — bearer-authenticated.

## Cookie flags
- `HttpOnly`, `SameSite=Strict`.
- `Secure=true` only under TLS. On HTTP loopback `Secure=false` with a
  rationale comment in the middleware (browsers drop `Secure` cookies over
  plain HTTP).

## Other
- Request ID propagated; OTel-compatible `traceparent`.
- Panic recovery per handler.
- Access log goes to stderr, separate from the application log.
