// Package middleware holds HTTP middleware for serve. Today that is the
// rate limiter (ratelimit.go): a token bucket per client IP (100/min by
// default, loopback exempt) and per auth token (300/min), wired by
// internal/web.NewServer since PITF-100. The rest of the original design
// placed here (token-generation caching, CSRF tokens, a body limit,
// request IDs, panic recovery) is not built (PITF-087). The other
// controls that run live in internal/web: the security headers with CSP
// nonces (server.go), the browser guard against cross-site requests and
// DNS rebinding (browserguard.go), and the OIDC role check
// (internal/web/auth).
package middleware
