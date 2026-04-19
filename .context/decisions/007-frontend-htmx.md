---
id: 007
title: HTMX + Alpine + Tailwind, no SPA, no Node in build
status: accepted
date: 2026-04-19
phase: F0
---

# ADR-007: HTMX + Alpine + Tailwind, no SPA, no Node in build

## Context
The dashboard needs to be navigable from a single static binary without
requiring a Node toolchain at build time. Operators should be able to
open it on an air-gapped jump host.

## Decision
Render from `html/template`. Interactivity via HTMX (AJAX/SSE via HTML
attributes) and Alpine.js for local state. Tailwind is **precompiled**
(CSS committed to `internal/web/static/`). All assets are embedded via
`embed.FS`.

## Consequences
### Positive
- Zero Node in CI.
- Single binary ships everything.
- Server-rendered templates are easy to reason about and audit.

### Negative / trade-offs
- Limited UI complexity; not suitable for heavy client-side dashboards.
- Tailwind updates require an out-of-band recompile step.

## Alternatives considered
- React / Vue SPA (rejected: adds Node to build).
- Pure server-rendered with no JS (rejected: SSE live updates require at
  least lightweight JS).

## References
- `internal/web/`; `.context/web.md`.
