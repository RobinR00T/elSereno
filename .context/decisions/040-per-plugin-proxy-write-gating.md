---
id: 040
title: Per-plugin proxy write-gating matrices (s7/enip/bacnet/dnp3/iec104/hartip/fox/atg)
status: accepted
date: 2026-04-19
phase: F5
---

# ADR-040: Per-plugin proxy write-gating matrices

## Context
F4 shipped eight ICS plugins (s7, enip, bacnet, dnp3, iec104, hartip,
fox, atg) with **pass-through** proxy handlers. The Modbus plugin
already enforces a wire-layer write-ban (ADR-030). The pass-through
was an acceptable F4 posture because the default build is read-only
across the board and F4's remit was fingerprinting + dashboard; F5
now adds writes, so the pass-through is a liability if an operator
ever points the proxy at a live device.

## Decision
Each of the 8 F4 plugins gains a **Category** classifier in its wire
package (`internal/protocols/<proto>/wire/categories.go`) modelled on
Modbus's: `CategoryRead`, `CategoryWrite`, `CategoryUnknown` (and
protocol-specific extras like `CategoryDiagnostic` for DNP3 /
IEC-104, `CategoryMEI`-analogue for ENIP service codes). The default
proxy handler (compiled into the default build) short-circuits every
non-Read frame with the protocol-appropriate "refused" response:

| Plugin  | Port      | Refusal frame                                      |
|---------|-----------|----------------------------------------------------|
| s7      | 102       | S7 negative-ack (PDU function reject)              |
| enip    | 44818     | Encapsulation status 0x0009 (`InvalidLength`) or   |
|         |           | CIP general status 0x08 (`Service not supported`)  |
| bacnet  | 47808/udp | BACnet Error-PDU with error-class=service, code=  |
|         |           | 4 (`inconsistent-parameters`)                      |
| dnp3    | 20000     | application-layer IIN2.NO_FUNC_CODE_SUPPORT        |
| iec104  | 2404      | S-format supervisory ACK + disconnect              |
| hartip  | 5094      | session-close with reason "unsupported-command"    |
| fox     | 1911/4911 | TCP close after "fox a 0 -1 fox denied\n"          |
| atg     | 10001     | echoes `9999FF1B` (standard Veeder-Root `Data       |
|         |           | Error` response)                                   |

All eight classifiers are used by the default build to refuse writes
at the wire layer. Under `-tags offensive` the plugin exposes an
alternative `WriteGatedHandler` that routes every mutating frame
through `offensive/confirm.Authorize` (ADR-039); allowed frames
forward, denied frames hit the same refusal table as the default
build.

### Fuzz corpus
Each new wire classifier has at least one fuzz target seeded with the
existing wire corpus. The classifier must return `CategoryUnknown`
(which defaults to "refuse") for any malformed input and must not
panic.

## Consequences

### Positive
- Removes the last F4 pass-through carry-over: the default build now
  has a wire-layer write-ban for every TCP-based plugin.
- Offensive writes go through the same confirm wrapper regardless of
  whether they are issued by the dedicated `elsereno write <proto>`
  CLI or forwarded via the proxy.
- The refusal responses are protocol-native, so the client gets an
  intelligible failure rather than a mid-stream TCP RST.

### Negative / trade-offs
- ATG's Data-Error (`9999FF1B`) is the closest the protocol has to a
  "refused" reply; operators who see it need to check the audit chain
  to distinguish "device replied Data Error" from "proxy refused".
  Documented in `.context/protocols/atg.md`.
- BACnet Error-PDU requires the BVLC+NPDU envelope, which costs ~40
  lines of marshalling we did not need for F4 (probe was pure
  Who-Is).

## Alternatives considered
- **Keep F4 pass-through under the default build**: rejected. An
  operator who runs `elsereno proxy s7` today with a live PLC would
  happily forward write frames, even without `-tags offensive`. The
  safety argument dominates.
- **Refuse via TCP close**: faster to implement but breaks intelligent
  clients (they retry, the retry gets refused, etc.). Native refusal
  is both cheaper for the client and clearer in logs.

## References
- ADR-030 (Modbus wire-layer ban, the pattern being generalised).
- ADR-039 (triple-confirm wrapper).
- Protocol specs: IEC 61131 / ISO 15745 (S7), ODVA Vol 1+2 (CIP),
  ASHRAE 135 (BACnet), IEEE 1815 (DNP3), IEC 60870-5-104,
  HART-IP 7.7 spec, Niagara Fox `fox` protocol notes, Veeder-Root
  TLS-350 manual (ATG).
