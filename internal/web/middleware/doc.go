// Package middleware is reserved for HTTP middleware and holds none
// yet. The design placed here token-generation caching (PITF-034),
// CSRF tokens, a body limit, rate limits (per-IP 100/min loopback-exempt
// and per-token 300/min), request IDs and panic recovery; none of those
// exists (PITF-087). What runs today lives in internal/web: the
// security headers with CSP nonces (server.go), the browser guard
// against cross-site requests and DNS rebinding (browserguard.go), and
// the OIDC role check (internal/web/auth).
package middleware
