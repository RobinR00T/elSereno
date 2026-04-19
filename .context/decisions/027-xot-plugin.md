---
id: 027
title: XOT (RFC 1613) plugin — parser from scratch, read-only fingerprint
status: accepted
date: 2026-04-19
phase: F2
---

# ADR-027: XOT (RFC 1613) plugin — parser from scratch, read-only fingerprint

## Context
X.25 over TCP remains deployed on legacy industrial and financial
networks (X.28 PADs, legacy ATM networks, older fiscal/lottery
networks). ElSereno's exposure audit needs to identify XOT endpoints
and report what kind of X.25 DCE is behind them without touching the
virtual circuit beyond "is it there, and what does it reject with".

The brief mandates parsers from scratch under
`internal/protocols/<name>/wire/` (section 5 "Red y protocolos").
Importing an existing X.25 library would conflate correctness with
upstream's maintenance state (PITF-011) and would drag in full X.25
semantics we do not need.

## Decision
- Implement the RFC 1613 envelope (4-byte header: 2-byte version =
  0x0000, 2-byte big-endian length) and the subset of X.25 Packet
  Type Identifiers needed to fingerprint a target:
  Call Request / Call Accepted / Clear Request(Indication) /
  Clear Confirmation / RR / RNR / REJ / Interrupt / Reset / Restart /
  Diagnostic. Data packets (PTI bit 0 == 0) collapse into a single
  `PacketData` type.
- Reject any payload longer than RFC 1613's 4096-byte maximum or
  shorter than 3 bytes; reject any non-zero Version byte.
- Probe logic: open TCP, send a minimal Call Request (LCN=1, no
  addresses, no facilities), read one response frame, classify.
  Call Accepted bumps the capability factor; Clear Indication
  extracts cause/diag; silent close is treated as an info-level
  finding.
- The REPL hook is declared but not yet bound; it arrives with the
  generic REPL framework in F4.
- The proxy handler forwards frames in both directions without
  instrumentation (F3 adds the proxy framework's hook points).
- A companion Go simulator at `simulators/xot/` lets the integration
  suite and manual operators exercise the plugin without a real
  X.25 gateway.
- Offensive operations (establishing a VC, sending user data,
  exploring connected endpoints) are deferred to F5 behind
  `-tags offensive`.

## Consequences
### Positive
- Zero external dependencies for the parser.
- Fuzz targets (FuzzParseHeader, FuzzParseX25, FuzzFrameRoundTrip)
  exercise the wire format with stdlib-only seeds.
- The plugin honours the read-only discipline: probes close the
  connection immediately after the response classification.

### Negative / trade-offs
- Full X.25 semantics (P(R)/M/P(S) windowing, multi-packet
  segmentation, facilities parsing) are not implemented. Findings
  record the packet type and cause code; deeper inspection is a
  future enhancement.
- Some legacy gateways may send RR before the Clear; our probe treats
  any non-Clear as "noise until the timeout" and records the first
  classifiable frame. Good enough for audit-grade findings.

## Alternatives considered
- **`github.com/vext01/libx25` (Go bindings)**: archived, no recent
  activity; violates PITF-011.
- **Using nmap's NSE `pad-discover`**: different semantic (PAD login
  sniff); also introduces an external-tool dependency we already
  serialise via SafeCommand for scan-list ingestion only.

## References
- RFC 1613 — Cisco Systems X.25 over TCP (XOT) — 1994.
- ITU-T Recommendation X.25 (Packet Layer Protocol) — 1996.
- `.context/protocols/xot.md` — operator-facing notes.
