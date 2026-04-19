---
id: 009
title: Plugin registration via init() + blank imports
status: accepted
date: 2026-04-19
phase: F0
---

# ADR-009: Plugin registration via `init()` + blank imports

## Context
Protocol plugins need a way to register themselves without forcing
`main.go` to enumerate them. The set differs between default and
`-tags offensive` builds.

## Decision
Each plugin package has an `init()` that calls `core.Register(...)`.
`cmd/elsereno/plugins.go` imports plugins with blank imports
(`_ "module/internal/protocols/modbus"`). `plugins_offensive.go` (behind
the `offensive` build tag) imports additional offensive plugins.

## Consequences
### Positive
- Adding a plugin is a two-line change (import + package).
- Build tags isolate what is compiled.
- No reflection; static linking keeps binary introspectable.

### Negative / trade-offs
- `init()` side effects must be limited to registration
  (`.context/conventions.md`).
- Two registration files to maintain.

## Alternatives considered
- Explicit registry construction in `main`: verbose, invites merge
  conflicts, and duplicates the build-tag split anyway.

## References
- `cmd/elsereno/plugins.go`, `cmd/elsereno/plugins_offensive.go`.
