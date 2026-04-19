---
id: 004
title: Offensive capabilities gated by -tags offensive
status: accepted
date: 2026-04-19
phase: F0
---

# ADR-004: Offensive capabilities gated by `-tags offensive`

## Context
Writes, exploits, credential harvesting, and dialling are legitimate for
authorised red-team engagements but carry high blast radius. The default
build must not ship any of them.

## Decision
Use the Go build tag `offensive` to gate the `offensive/` tree
(`write/`, `exploits/`, `harvest/`, `dial/`, `sandbox/`). Registration of
offensive plugins is in `cmd/elsereno/plugins_offensive.go`, also behind the
same tag. All offensive writes require triple confirmation; dialling
additionally requires `--dial-allowed`.

## Consequences
### Positive
- A default download / install of `elsereno` cannot mutate a target.
- Distribution of binaries remains safe for defenders and auditors.
- CI builds both variants (`build`, `build-offensive`) to catch bitrot
  (PITF-031).

### Negative / trade-offs
- Authors must remember to duplicate interface plumbing for both builds.
- Coverage data is split across variants; CI measures both.

## Alternatives considered
- A runtime flag (rejected: easier to flip, and the binary still ships the
  dangerous code paths).
- A separate binary `elsereno-offensive` (fine, but goreleaser matrix
  already handles this via the tag).

## References
- Project brief sections 5 and 7.
