---
id: 019
title: `.context/pitfalls.md` as a mandatory living catalogue
status: accepted
date: 2026-04-19
phase: F0
---

# ADR-019: `.context/pitfalls.md` as a mandatory living catalogue

## Context
Anti-patterns accumulate across a long-lived codebase. A one-off README
entry about a bug does not propagate to future contributors; a shared,
enforced catalogue does.

## Decision
- `.context/pitfalls.md` is a **mandatory reading** before any
  code/config change (enforced by `CLAUDE.md` + `CONTRIBUTING.md`).
- New anti-patterns are added using the `templates/pitfall.md` format
  (H2 + `Síntoma / Regla / Implementación correcta / Ver`).
- The `scripts/context-check.sh` detector ensures that docs don't
  reference "prior versions" (PITF-007), and enforces a floor of 36
  entries at F0.
- The detector itself skips `pitfalls.md` and code fences (PITF-036).

## Consequences
### Positive
- Institutional memory about bugs survives contributor turnover.
- The catalogue guides code review and new designs.

### Negative / trade-offs
- Requires discipline: contributors must write pitfalls as they find them.

## Alternatives considered
- Issue-tracker-only (rejected: too easy to ignore).
- In-code comments (rejected: diffused, not greppable, rot in place).

## References
- PITF-007, PITF-036; `CLAUDE.md`.
