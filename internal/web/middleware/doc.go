// Package middleware implements auth, token-generation caching
// (TTL 5 s; PITF-034), CSRF, CSP nonces, security headers, body limit,
// rate limits (per-IP 100/min loopback-exempt AND per-token 300/min),
// request ID propagation, and panic recovery.
package middleware
