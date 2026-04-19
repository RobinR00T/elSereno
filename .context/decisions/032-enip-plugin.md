---
id: 032
title: EtherNet/IP CIP plugin — read-only probe + fingerprint
status: accepted
date: 2026-04-19
phase: F4
---

# ADR-032: EtherNet/IP CIP plugin — read-only probe + fingerprint

## Context
EtherNet/IP CIP is an ICS/OT protocol commonly exposed on port 44818/tcp.
ElSereno needs a read-only fingerprint that (a) sends the smallest
valid request and (b) classifies the response without establishing
any stateful session the caller has to tear down.

## Decision
- From-scratch parser under `internal/protocols/enip/wire/`
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
- ODVA CIP Vol 2 (Encapsulation); Vol 7 (IP adaptation)
- `.context/protocols/enip.md`.
