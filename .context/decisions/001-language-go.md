---
id: 001
title: Go as the implementation language
status: accepted
date: 2026-04-19
phase: F0
---

# ADR-001: Go as the implementation language

## Context
ElSereno needs a statically linked single-binary tool with strong concurrency,
a robust standard library, a mature ecosystem of ICS/OT and security tooling,
and pragmatic cross-compilation for Linux and macOS on amd64/arm64.

## Decision
Implement ElSereno in Go 1.22+ with a pinned `toolchain` directive.

## Consequences
### Positive
- Single static binary per target (`CGO_ENABLED=0`) simplifies distribution.
- First-class context propagation, goroutines, and channels match the
  "many I/O-bound probes in parallel" workload.
- Mature ecosystem: `pgx`, `cobra`, `charmbracelet/bubbletea`, `memguard`,
  `gopacket` (reserved for vNext), `zerolog`.
- Fuzzing is part of the standard toolchain.

### Negative / trade-offs
- The SQLite variant requires CGO (ADR-012), which limits cross-compilation
  (PITF-006).
- No native sum-type / enum; we emulate with typed constants and CHECK
  constraints (PITF-022, PITF-030).

## Alternatives considered
- **Rust**: better type system, but slower compile cycles, smaller ICS
  ecosystem today, and CGO equivalents still painful.
- **Python**: weak static guarantees for a security tool; packaging a
  single binary is awkward.

## References
- Project brief section 5.
