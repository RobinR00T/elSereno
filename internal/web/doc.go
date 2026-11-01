// Package web hosts the dashboard HTTP server.
//
// http.Server is configured with the full set of timeouts
// (ReadHeaderTimeout=5s, ReadTimeout=30s, WriteTimeout=30s,
// IdleTimeout=120s, MaxHeaderBytes=16KiB) and a 1 MiB body limit.
// Auth today is Bearer-token for every endpoint (API and HTML alike);
// no request is cookie- or CSRF-protected yet. The dual-auth design
// (ADR-014: Bearer for /api/v1/*, cookie + CSRF for HTML) and its
// vault-derived CSRF key (ADR-017) are pre-provisioned but the
// middleware is not wired (PITF-087).
//
// See internal/web/handlers, internal/web/middleware, and
// internal/web/templates.
package web
