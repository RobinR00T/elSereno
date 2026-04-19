---
id: 034
title: DNP3 plugin — read-only probe + fingerprint
status: accepted
date: 2026-04-19
phase: F4
---

# ADR-034: DNP3 plugin — read-only probe + fingerprint

## Context
DNP3 is an ICS/OT protocol commonly exposed on port 20000/tcp.
ElSereno needs a read-only fingerprint that (a) sends the smallest
valid request and (b) classifies the response without establishing
any stateful session the caller has to tear down.

## Decision
- From-scratch parser under `internal/protocols/dnp3/wire/`
  covering the wire header + classification helpers.
- Probe sends one request, reads one response, closes the connection.
- Scoring: ADR-006 factor defaults with per-protocol risk + impact
  baked in via the plugin's `buildFinding`.
- Write operations (where the protocol exposes them) are F5 with
  triple-confirm semantics.

## Consequences
### Positive
- Zero external deps (stdlib-only parser).
- Fuzz target covers the header surface against adversarial bytes.
- Pattern mirrors s7/enip/bacnet/dnp3/iec104/hartip/fox/atg for
  review parity.

### Negative / trade-offs
- Deep-parse of reply bodies is deferred — we record presence +
  first-level classification, not full protocol semantics.

## Alternatives considered
- Importing an existing library (PITF-011): declined per the brief's
  parser-from-scratch discipline.

## References
- IEEE 1815 (2012) data link + application
- `.context/protocols/dnp3.md`.
