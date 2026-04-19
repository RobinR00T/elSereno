---
id: 016
title: Windows is out of scope for v1
status: accepted
date: 2026-04-19
phase: F0
---

# ADR-016: Windows is out of scope for v1

## Context
A cross-platform tool that also supports Windows multiplies CI matrix,
testing burden, and platform-specific code paths (raw sockets, seccomp
alternative, path handling).

## Decision
v1 supports Linux and macOS on amd64/arm64. Windows is deferred to vNext.
`.github/workflows/ci.yml` does not include Windows runners. The
`NON-GOALS.md` lists this explicitly.

## Consequences
### Positive
- Focus on delivering the core domain features faster.
- Fewer test escapes from cross-platform assumptions.

### Negative / trade-offs
- Windows operators must wait.

## Alternatives considered
- Supporting Windows from day one (rejected: too much scope).

## References
- `NON-GOALS.md`.
