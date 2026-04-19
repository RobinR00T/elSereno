---
id: 002
title: MIT license
status: accepted
date: 2026-04-19
phase: F0
---

# ADR-002: MIT license

## Context
We need a permissive license that allows both commercial and academic use
while being well understood by downstream consumers.

## Decision
Release under the MIT License. See `LICENSE`.

## Consequences
### Positive
- Simple, permissive, widely understood.
- Compatible with most corporate procurement processes.

### Negative / trade-offs
- No copyleft protection; downstream derivatives may be closed.

## Alternatives considered
- **Apache-2.0**: also fine, and includes an explicit patent grant, but
  introduces a NOTICE obligation we prefer to avoid for a small project.
- **GPL-3.0**: stronger copyleft than we want for a CLI tool.

## References
- `LICENSE`.
