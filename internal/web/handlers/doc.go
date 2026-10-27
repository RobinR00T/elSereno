// Package handlers holds the HTTP handlers for /healthz, /readyz,
// /metrics, /, and /api/v1/*. No /login or /logout routes exist yet:
// authentication is Bearer-token only (the cookie-session design is
// PITF-087, not built).
package handlers
