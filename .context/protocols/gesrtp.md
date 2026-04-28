---
phase: v1.20
status: implemented
last-updated: 2026-04-28
token-budget: 1000
protocol-name: gesrtp
default-port: 18245/tcp
---

# GE-SRTP

## TL;DR
ElSereno's `gesrtp` plugin sends a single 56-byte CONNECTION INIT
mailbox (byte 0 = 0x02, rest zero) on TCP/18245 and classifies the
response by SRTP type byte (0x03 = response). v1.20 chunk 3 ships
read-only fingerprint plus a wire-layer write-ban proxy that
replies with a 56-byte mailbox carrying a non-zero status byte.

## Spec references
- Rapid7 nmap NSE script `gesrtp-info` — canonical public
  reverse engineering.
- Conpot project — GE simulator fixtures.
- ICS-CERT advisories on GE Fanuc PACSystems lacking authentication.

## Wire format (summary)
SRTP is **mailbox-framed**: every request and response is exactly
56 bytes for the basic service-request set. The plugin treats all
bytes other than byte 0 as opaque for v1.20 chunk 3 — the full
layout (with packet sequencing + service-request payloads) lands
when offensive write services are wired.

```
Offset  Field                  Value (CONNECTION INIT)
0       Type                   0x02 = request, 0x03 = response
1..7    reserved               0
8..9    Packet number          0 (set on follow-up service requests)
10..11  Sequence number        0
30..31  Service request code   0 (set on follow-up; 0x21 = read CPU long status)
32..49  Service-specific       0
50..55  end of mailbox         0
```

## Fingerprint strategy
One-shot probe over TCP. Send a 56-byte CONNECTION INIT mailbox
(byte 0 = 0x02, rest zero); read 56 bytes of response. Classify by
the response type byte (0x03). Public protocol documentation is
sparse, so deeper service-code probing (CPU model identification
via service 0x21) is deferred — the plugin captures the fact that
"a 56-byte SRTP mailbox came back" as the fingerprint signal.

## Read operations (default build)
- `probe`: dials TCP/18245, sends BuildConnectionInit (56 bytes,
  byte 0 = 0x02), reads exactly 56 bytes, classifies via
  ClassifyResponse.

## Write / dial operations (offensive build tag)
Deferred. SRTP supports the following write-class service request
codes (from public reverse engineering):
- `0x07` Write system memory
- `0x09` Write PLC memory
- `0x0F` Write program block
- `0x10` Write memory by symbolic name
- `0x18` RUN command
- `0x19` STOP command
- `0x1A` Reset command

A future offensive plugin would gate per-(service-code,
memory-area) (analogous to Modbus per-FC + per-address-range) and
emit `audit-chain` events per service-request mailbox. Triple-
confirm + audit-chain emission per ADR-009.

## REPL commands (planned)
- See the generic REPL framework. A future REPL would expose the
  connection-init response payload (packet number, sequence
  number, version flags) and let operators issue
  service-code-0x21 reads against test PLCs.

## Proxy hooks
Wire-layer write-ban: the default-build handler reads the
client's 56-byte mailbox and replies with a 56-byte mailbox
carrying byte 0 = 0x03 (response) + byte 42 = 0x01 (non-zero
"status / minor error" indicator). Does NOT forward — defence-in-
depth fail-closed pattern matching the Modbus / S7 / EtherNet/IP
proxy idioms.

## Scoring contribution
factors{protocol_risk:80, exposure:75, auth_state:95, capability:30
(70 on SRTP reply), impact_class:75, cve_exposure:0}. impact_class
75 reflects factory-floor + SCADA blast radius (RUN/STOP, write
program block / system memory). auth_state 95 because SRTP has no
native authentication.

Note: capability lift on positive identification is **70** for
gesrtp (vs 75 for finsudp/slmp) because the connection-init
classifier doesn't yet decode the response payload — operators
have less actionable detail on the controller model. A future
service-0x21 read would push this to 75.

## Sentinel errors (wire package)
- ErrShortFrame: < 56-byte response.
- ErrNotResponse: byte 0 of response is not 0x03.

These surface to the operator-facing note via `classifyParseError`
(plugin layer): "short SRTP frame (N bytes)" or "SRTP response
type byte not 0x03".
