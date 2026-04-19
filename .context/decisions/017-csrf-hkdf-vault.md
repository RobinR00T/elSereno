---
id: 017
title: CSRF key derived from vault via HKDF; serve requires vault unlocked
status: accepted
date: 2026-04-19
phase: F0
---

# ADR-017: CSRF key derived from vault via HKDF; `serve` requires vault unlocked

## Context
CSRF protection needs a stable-per-deployment secret. Storing yet another
long-lived secret multiplies attack surface; deriving from the vault
master key reuses already-protected material.

## Decision
- CSRF key = `HKDF-SHA256(master_key, info="elsereno/csrf/v1")`.
- `elsereno serve` requires the vault to be **unlocked** (not
  auto-initialised). If the vault is not initialised, `serve` exits with a
  clear message pointing at `vault init`; if locked, at `vault unlock`.
- This resolves the PITF-002 circular dependency (CSRF key derivation
  requires the vault; we don't auto-create the vault).
- Auto-creation of critical state is banned (PITF-021).

## Consequences
### Positive
- One less long-term secret to protect and rotate.
- Explicit initialisation flow removes silent-vault-creation bugs.

### Negative / trade-offs
- First-time setup has more steps (`vault init`, `vault unlock`, `serve`).

## Alternatives considered
- Generate CSRF key at first start and persist separately: more secrets,
  more rotation paths.
- Derive from a config-file string: then the string is the secret and we
  are back to square one.

## References
- PITF-002, PITF-021; ADR-014, ADR-018.
