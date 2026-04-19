---
id: 015
title: Audit hash chain canonicalisation via JCS (RFC 8785)
status: accepted
date: 2026-04-19
phase: F0
---

# ADR-015: Audit hash chain canonicalisation via JCS (RFC 8785)

## Context
A hash chain needs a canonical byte representation per entry so that two
verifiers compute the same hash. JSON has no canonical form by default.

## Decision
- Use **JCS (RFC 8785)** via `github.com/gowebpki/jcs`.
- Canonicalised fields (exact list to avoid PITF-014): `id, occurred_at,
  actor, event_type, payload, prev_hash`.
- `entry_hash = SHA-256(JCS(canonical))`.
- `entry_hash` is **excluded** from canonicalisation because it is
  derived.

## Consequences
### Positive
- Deterministic hashes across languages and library versions.
- Explicit field list removes a large class of silent divergence.

### Negative / trade-offs
- JCS is a small, relatively new library — tracked under PITF-011.

## Alternatives considered
- Custom canonicalisation: reinventing JCS is a recipe for bugs.
- Hashing the raw JSON bytes: non-deterministic (key order, whitespace,
  Unicode normalisation).

## References
- PITF-014; `.context/persistence.md` audit_log.
