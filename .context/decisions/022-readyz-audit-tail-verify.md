---
id: 022
title: `/readyz` verifies the audit chain tail, not the full chain
status: accepted
date: 2026-04-19
phase: F0
---

# ADR-022: `/readyz` verifies the audit chain tail, not the full chain

## Context
A naive `/readyz` that verifies the entire audit chain grows linear in
chain length; after a few months of heavy use it dominates readiness
probe time, and Kubernetes-style probes start failing (PITF-025).

## Decision
- `/readyz` verifies the tail of the audit chain:
  `readyz.audit_tail_entries` entries (default `100`).
- If the chain has fewer entries than `N`, verify all of them and return
  healthy with an informational note (no error).
- The full-chain verification remains available via
  `elsereno audit verify` (operator-invoked).

## Consequences
### Positive
- Readiness stays O(1) regardless of chain length.
- Operator still has a CLI path to do the full check.

### Negative / trade-offs
- A corruption older than the tail window is caught only by explicit
  verification.

## Alternatives considered
- Cache the last-verified tip: adds state to verify. Rejected to keep
  readiness stateless.

## References
- PITF-025; `.context/persistence.md`.
