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
- Rapid7 nmap NSE script `gesrtp-info`: canonical public
  reverse engineering.
- Conpot project, GE simulator fixtures.
- ICS-CERT advisories on GE Fanuc PACSystems lacking authentication.

## Wire format (summary)
SRTP is **mailbox-framed**: every request and response is exactly
56 bytes for the basic service-request set. The plugin treats all
bytes other than byte 0 as opaque for v1.20 chunk 3, the full
layout (with packet sequencing + service-request payloads) lands
when offensive write services are wired.

```
Offset  Field                  Value (CONNECTION INIT)
0       Type                   0x02 = request, 0x03 = response
1..7    reserved               0
8..9    Packet number          0 (set on follow-up service requests)
10..11  Sequence number        0
30..41  Service-specific       0
42      Service request code   0 on init; 0x21 (Read PLC Long Status) in the follow-up
43..49  Service-specific       0 on init; 43..45 = 01 03 01 in the follow-up
50..55  end of mailbox         0
```

## Fingerprint strategy
Send a 56-byte ALL-ZERO CONNECTION INIT mailbox; a GE PLC answers a
56-byte mailbox with byte 0 = 0x01 (PITF-067: an earlier version sent
0x02 and expected 0x03, the OPERATION message types). On a positive
init, send one 0x21 Read PLC Long Status (operation request, byte 0 =
0x02) and read the model and firmware from its 0x03 operation reply
(accepted since 2026-10-07; the probe used to demand 0x01 there).

**v1.21 chunk 4**: model-hint extraction. After classification, the
plugin runs `ExtractModelHint` on the full response buffer to
recover any embedded GE PLC family string (22 canonical prefixes in
`wire.go`: PACSystems, IC693, IC695, IC697, IC200, RX3i, RX7i and the
per-CPU tokens). When a hint is found, it
folds into the finding hash and lifts capability from 70 to 75.

## Read operations (default build)
- `probe`: dials TCP/18245, sends BuildConnectionInit (56 zero
  bytes), reads exactly 56 bytes, classifies via ClassifyResponse
  (byte 0 = 0x01); on a positive init, sends BuildReadLongStatus and
  parses the reply with ParseLongStatus.

## Write / dial operations (offensive build tag)
Shipped (`offensive/write/gesrtp`, TCP/18245). The gate classifies
each fixed 56-byte SRTP mailbox by its service-request code: read
services (READ_SYS_MEM, GET_INFO, ...) pass; a mutating service
(e.g. `0x07` WRITE_SYS_MEM, `0x23` SET_PLC_RUN, `0x40` PROG_LOAD)
is admitted only when allowlisted via `--gesrtp-service <byte>`.
SRTP has no per-request NAK, so a refusal CLOSES the connection
(fail-closed). Wire from `internal/protocols/gesrtp/wire` (Palatis
dissector). See `docs/protocols/gesrtp.md` for the full CLI +
`scripts/demo-gesrtp-proxy.sh` for an end-to-end demo. Triple-
confirm + audit-chain emission per ADR-039.

## REPL commands (planned)
- See the generic REPL framework. A future REPL would expose the
  connection-init response payload (packet number, sequence
  number, version flags) and let operators issue
  service-code-0x21 reads against test PLCs.

## Proxy hooks
Wire-layer write-ban: the default-build handler reads the
client's 56-byte mailbox and replies with a 56-byte mailbox
carrying byte 0 = 0x03 (response) + byte 42 = 0x01 (non-zero
"status / minor error" indicator). Does NOT forward, defence-in-
depth fail-closed pattern matching the Modbus / S7 / EtherNet/IP
proxy idioms.

## Scoring contribution
factors{protocol_risk:80, exposure:75, auth_state:95, capability:30
(70 on SRTP reply, **75 when a model hint is extracted**),
impact_class:75, cve_exposure:8 baseline}. cve_exposure is raised
by cve.ForGESRTP when the model hint names a CPU an advisory
lists, per CVE (NVD-verified): RX3i CPE305/310/330/400 + CRU320 ->
CVE-2018-8867 + CVE-2019-13524; CPE100/115/302/410 -> 13524 only;
RSTi-EP CPE100 / RXi CPU320 -> 8867 only. Family-only hints, RX7i,
CPU310/CPL410, Series 90 and VersaMax get the baseline only. impact_class 75
reflects factory-floor + SCADA blast radius (RUN/STOP, write
program block / system memory). auth_state 95 because SRTP has no
native authentication.

Capability lift breakdown:
- 30: no SRTP reply.
- 70: SRTP-shape reply with no embedded model hint.
- 75: SRTP-shape reply with a recognised GE PLC family hint
  (IC693 / IC695 / IC697 / IC200 / RX3i / RX7i / PACSystems), 
  parity with finsudp / slmp.

## Sentinel errors (wire package)
- ErrShortFrame: < 56-byte response.
- ErrNotResponse: byte 0 of response is not 0x03.

These surface to the operator-facing note via `classifyParseError`
(plugin layer): "short SRTP frame (N bytes)" or "SRTP response
type byte not 0x03".
