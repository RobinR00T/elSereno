---
id: 030
title: Modbus/TCP plugin — read-only default, FC-level write ban
status: accepted
date: 2026-04-19
phase: F3
---

# ADR-030: Modbus/TCP plugin — read-only default, FC-level write ban

## Context
Modbus/TCP has no authentication. Any client that can reach port
502 can read and write. Deploying ElSereno on an OT network means
exposing a protocol-aware interceptor that MUST NOT coerce mutable
state. The ban has to be at the wire layer, not the config layer:
allowing writes via an environment variable or YAML toggle would
make the next mis-edited scope.yaml a safety event.

## Decision
- The plugin's ProxyHandler is the single point of enforcement. Each
  frame is parsed; the FunctionCode goes through wire.Classify, and
  CategoryWrite (FC 5/6/15/16/22/23, plus the write-file-record and
  mask-write-register variants) short-circuits to an
  IllegalFunction exception sent back to the client. The upstream
  device never sees the write frame.
- FC 43 (Encapsulated Interface Transport) is a special case: the
  proxy only forwards sub-code 0x0E (Read Device Identification),
  which is read-only. Any other MEI sub-code is blocked.
- FC 8 (Diagnostics) is treated as CategoryUnknown in F3; passes
  through unmodified. F5 will tighten this with per-sub-code rules
  because some diagnostics modes can force remote restart.
- The Probe is read-only by construction: FC 1 (Read Coils, 1 coil
  at address 0) as the minimal legal read, plus an opportunistic
  FC 43/14 for device-identification strings.

## Consequences
### Positive
- Writing code literally cannot reach the wire through ElSereno's
  proxy. A bug in a higher layer would have to bypass wire.Classify
  (tests cover every write FC in the catalogue).
- The same category table drives both the proxy ban and future
  offensive plugins: F5 will add a CategoryWrite-enabler behind
  `-tags offensive` + triple confirm, referencing the same constants.

### Negative / trade-offs
- Diagnostics (FC 8) is permissive for now. Documented in the
  protocol doc and in the ADR so it's not a hidden surprise.
- The proxy emits IllegalFunction for blocked writes; a real PLC
  would return a transport-layer error for unknown FC. Using
  IllegalFunction is correct per the spec — the client sees a
  legitimate protocol response and can handle it without special
  casing.

## Alternatives considered
- **Allow writes with a config flag**: rejected per the Context
  reasoning. The safety argument dominates.
- **Return a transport-layer error (close conn)**: more confusing
  to operators and harder to correlate in logs.

## References
- MODBUS Messaging on TCP/IP V1.0b, §5.
- MODBUS Application Protocol Specification V1.1b3, §6.
- `.context/protocols/modbus.md` — operator-facing notes.
