---
phase: v1.21
status: implemented
last-updated: 2026-04-28
token-budget: 800
protocol-name: mbustcp
default-port: 10001/tcp
---

# M-Bus over TCP

## TL;DR
ElSereno's `mbustcp` plugin sends a 5-byte REQ_UD2 short frame
to broadcast primary address 0xFE on TCP/10001 and folds the
parsed manufacturer ID + medium byte from the RSP_UD long-frame
response into the finding hash. ACK-only responses are also
positive identifications. v1.21 chunk 2 ships read-only
fingerprint plus a wire-layer write-ban proxy that replies with
a single-byte ACK (0xE5).

## Spec references
- EN 13757-3: M-Bus application layer (canonical).
- EN 13757-4: Wireless M-Bus (informational).
- "M-Bus: A documentation" v4.8 (community reference).

## Wire format (summary)
5-byte short-frame request, 1-byte ACK or 21+-byte long-frame
response. Frame layout in `internal/protocols/mbustcp/wire/wire.go`.

Manufacturer code is 3 ASCII letters packed into 16 bits:
`M = (c1-'A'+1)*32^2 + (c2-'A'+1)*32 + (c3-'A'+1)`.

## Fingerprint strategy
One-shot probe over TCP. The 3-letter manufacturer code ("ABB",
"KAM" Kamstrup, "ELS" Elster, "SEN" Sensus, etc.) plus the
medium byte (0x02=electricity, 0x03=gas, 0x07=water, 0x16=cold
water, 0x17=heat-cost-allocator, etc.) folded into the finding
hash.

## Read operations (default build)
- `probe`: dials TCP/10001, sends BuildREQUD2(0xFE), reads
  up to 256 bytes, classifies via IsACK / IsRSPUD, parses on
  RSP_UD via ParseRSPUD.

## Write / dial operations (offensive build tag)
Deferred. M-Bus supports SND_UD (CI=0x51/0x52) for parameter
writes, SET_BAUDRATE (CI=0xB8..0xBC) for re-bauding the meter
(DoS), and various data-record writes.

## REPL commands (planned)
- See the generic REPL framework. Expose MeterInfo fields.

## Proxy hooks
Wire-layer write-ban: reads the first M-Bus frame and replies
with a single-byte ACK (0xE5). Matches the protocol's own
link-layer ACK idiom — the meter says "got it" but no data is
returned, which is the closest "request denied" surface.

## Scoring contribution
factors{protocol_risk:70, exposure:70, auth_state:90, capability:30
(70 on M-Bus reply), impact_class:60, cve_exposure:0}.
- protocol_risk 70 (vs 80 for industrial PLCs) reflects metering
  rather than direct kinetic control.
- impact_class 60 reflects billing accuracy + privacy-of-
  consumption-data blast radius.

## Sentinel errors (wire package)
- ErrShortFrame, ErrBadStart, ErrLengthMismatch, ErrBadStop,
  ErrChecksumMismatch, ErrNotVarDataResponse.
