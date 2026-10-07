---
phase: v1.22
status: implemented
last-updated: 2026-10-04
token-budget: 800
protocol-name: codesys
default-port: 1217/tcp
---

# CoDeSys V3

## TL;DR
ElSereno's `codesys` plugin sends the 4-byte Block Driver magic
(0xE8170100, LE on the wire: 00 01 17 e8) on TCP/1217 and
classifies the response by either:
- a reply that starts with the Block Driver magic (a Block Driver
  frame; an exact copy of our 4 bytes is rejected as an echo,
  PITF-071), or
- Canonical CoDeSys banner substring (CoDeSys / CODESYS /
  3S-Smart / 3S-CoDeSys / CmpHostname / CmpAppBP / CmpRuntime).

The magic was corrected 2026-10-04 from the bogus 0xCDCDCDCD
(MSVC uninitialised-heap fill) to the real value, validated
against the Tenable gateway PoC, the Kaspersky ICS-CERT paper and
a real capture (cds3.pcapng). A bare magic is not a full frame, so
the banner path is the default-build signal; the eliciting
channel-open probe ships opt-in as `codesys-active` (PITF-068).

v1.22 chunk 2 ships read-only fingerprint with a fail-closed
proxy.

## Spec references
- ICS-CERT ICSA-12-242-01 / 19-080-01 / 21-014-04, CVE families.
- nmap NSE script `codesys-info` (community).
- Open-source clients: libcodesys-py, codesys-rs.

## Wire format (summary)
4-byte Block Driver magic `0xE8170100` (LE on the wire:
`00 01 17 e8`) opens every CoDeSys V3 Block Driver frame,
followed by a 4-byte LE total length (includes the 8-byte
header). Frame layout in
`internal/protocols/codesys/wire/wire.go`. Deeper Layer-3 /
Layer-4 / Layer-7 APDU stack is out of scope for v1.22 chunk 2.

## Fingerprint strategy
One-shot probe over TCP. Send the 4-byte magic, read up to 1024
bytes. Two positive-ID paths: a Block Driver frame (magic prefix,
not an echo of our probe) and gateways that prefix a plain-text
greeting before the binary handshake (banner substring match).

## Read operations (default build)
- `probe`: dials TCP/1217, sends BuildHello (4 bytes), reads up
  to 1024 bytes, classifies via Classify (BlockDriver magic OR
  banner substring).

## Active probe (opt-in: codesys-active)
- `codesys-active` (DefaultPort 0, OptIn): sends the channel-open
  PDU (wire.BuildChannelOpen; validated against the Tenable PoC, not a
  live 1217 gateway), and confirms by a Block-Driver-framed reply; a
  CoDeSys banner counts too, noted as banner evidence. Read-only detection
  (opens a channel to read the reply, no service request). Kept
  out of the default sweep; run via `--plugin codesys-active`. The
  frame is ported byte-for-byte from the Tenable PoC and validated
  against it (wire/channel_test.go); not yet exercised vs a live
  gateway, so the reply is classified by the magic (PITF-068).

## Write / dial operations (offensive build tag)
Shipped (`offensive/write/codesys`, TCP/1217+11740). CoDeSys v3
has no transport-layer length a gate can trust, so the handler
does NOT parse L3/L4: it buffers the reassembled stream and, via
`wire.ScanL7`, locates every L7 service header (magic `0x55cd`/
`0x7557`) and classifies each `(service, cmd)`. Reads pass; a
mutating command is admitted only when allowlisted via
`--codesys-command SERVICE:CMD`; anything else closes the
connection (fail-closed). A real write header must carry the magic
to be parsed by the PLC, so it is always located: a decoy read
cannot hide a write. Wire from the fridgebuyer/codesys3-dissector.
See `docs/protocols/codesys.md` + `scripts/demo-codesys-proxy.sh`.
Triple-confirm + audit-chain emission per ADR-039.

## REPL commands (planned)
- See the generic REPL framework. A future REPL would issue
  CmpHostname / CmpInformation read requests to enumerate the
  PLC runtime version + project name.

## Proxy hooks
Fail-closed: the proprietary tag-length-value stack is not
implemented in v1.22 chunk 2; the default-build proxy refuses
sessions immediately rather than relay bytes that may or may not
be valid CoDeSys frames.

## Scoring contribution
factors{protocol_risk:80, exposure:75, auth_state:85, capability:30
(70 on CoDeSys reply), impact_class:75, cve_exposure:10}.
- protocol_risk 80: soft-PLC runtime, kinetic effects.
- auth_state 85: CoDeSys V3 supports password / OAuth but many
  deployments don't enforce.
- impact_class 75: factory-floor PLC blast radius.
- cve_exposure 10: ICSA-12-242-01 / 19-080-01 / 21-014-04 are
  well-known CVEs in the family, first plugin to set
  cve_exposure non-zero by default.

## Sentinel errors (wire package)
- ErrShortFrame: < 4-byte response.
- ErrNotCoDeSys: response neither leads with magic nor carries
  a banner substring.
