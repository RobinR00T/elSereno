// Package web hosts the dashboard HTTP server.
//
// http.Server is configured with the full set of timeouts
// (ReadHeaderTimeout=5s, ReadTimeout=30s, WriteTimeout=30s,
// IdleTimeout=120s, MaxHeaderBytes=16KiB) and a 1 MiB body limit.
// Auth is dual (ADR-014): Bearer for /api/v1/*, cookie + CSRF for HTML.
// CSRF key is HKDF-derived from the vault master key (ADR-017).
//
// See internal/web/handlers, internal/web/middleware, and
// internal/web/templates.
package web
