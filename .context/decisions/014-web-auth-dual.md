---
id: 014
title: Web auth — Bearer for /api/v1, cookie+CSRF for HTML
status: accepted
date: 2026-04-19
phase: F0
---

# ADR-014: Web auth — Bearer for `/api/v1`, cookie + CSRF for HTML

## Context
The web surface serves two consumers: automation scripts hitting
`/api/v1/*` and the HTML dashboard. Both need revocable, rotatable
credentials; only the dashboard needs CSRF protection.

## Decision
- **API**: `Authorization: Bearer <token>`. Token: 32 B from
  `crypto/rand`, base64url, stored at `~/.elsereno/web-token` (0600). TTL
  `web.token_ttl_days` (default 30). **No CSRF.**
- **HTML**: `POST /login` exchanges Bearer for a cookie `HttpOnly,
  SameSite=Strict, Secure=<tls>`. Cookie embeds `token_generation` at
  issue time.
- `token_generation` is persisted in `web_state(key, token_generation,
  updated_at)` and is bumped with a Postgres transaction guarded by
  `pg_advisory_xact_lock(hashtext('web_state_token_rotate'))` and
  `UPDATE ... RETURNING` (PITF-026).
- On every request, the middleware compares the cookie's embedded
  generation with the current one. To avoid a DB round-trip per request
  (PITF-034), the current generation is cached with TTL
  `web.token_generation_cache_ttl` (default 5 s). After a rotation,
  cookies expire within that TTL.

## Consequences
### Positive
- Automation flows are simple (Bearer) and cannot be silently proxied
  (no CSRF vector because no ambient cookie).
- Web dashboard is CSRF-safe via a cookie with embedded generation and a
  CSRF token (ADR-017).
- Rotation is atomic, auditable, and invalidates all live cookies within
  TTL seconds.

### Negative / trade-offs
- A 5 s stale window after rotation.
- Two middleware paths to maintain.

## Alternatives considered
- Cookie-based for everything: would require CSRF for the API.
- Bearer-only everywhere: browsers can't set custom headers on
  navigation / form posts cleanly without SPA glue.

## References
- ADR-017; PITF-001, PITF-026, PITF-034; `.context/web.md`.
