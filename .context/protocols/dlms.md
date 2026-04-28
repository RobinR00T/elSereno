---
phase: v1.21
status: implemented
last-updated: 2026-04-28
token-budget: 800
protocol-name: dlms
default-port: 4059/tcp
---

# DLMS/COSEM

## TL;DR
ElSereno's `dlms` plugin sends a 37-byte DLMS-wrapper-framed
AARQ probe (8-byte wrapper + 29-byte canonical minimal AARQ
APDU) on TCP/4059 and classifies the response by wrapper version
(0x0001) + AARE tag (0x61). Wrapper-only positive ID also
counts. v1.21 chunk 3 ships read-only fingerprint plus a
wire-layer write-ban proxy that replies with a 16-byte
wrapper-framed AARE rejected-permanent.

## Spec references
- IEC 62056-46: DLMS Wrapper (Green Book §8.4).
- IEC 62056-53: COSEM application layer.
- IEC 62056-62: Interface classes catalogue.

## Wire format (summary)
8-byte wrapper (BE, version 0x0001 + 2x 16-bit wPort + 16-bit
length) + BER-encoded COSEM APDU. Frame layout in
`internal/protocols/dlms/wire/wire.go`.

## Fingerprint strategy
One-shot probe over TCP. The wrapper version (0x0001) plus AARE
tag (0x61) at the APDU start indicates a confirmed
DLMS/COSEM server. Wrapper-only responses (e.g., AARQ tag echo
or fault APDU) also count as positive ID — the server speaks
DLMS-wrapper but rejected our AARQ, common with HLS-locked
deployments.

## Read operations (default build)
- `probe`: dials TCP/4059, sends BuildAARQ (37 bytes), reads
  the 8-byte wrapper + declared APDU body (capped at 8192),
  classifies via ClassifyResponse / IsWrapperResponse.

## Write / dial operations (offensive build tag)
Deferred. DLMS supports SET-Request, ACTION-Request (canonically
`remote_disconnect()` on the disconnect-control object — opens
the service breaker remotely), tariff-schedule rewrites,
push-destination URL changes. Per-(class-id, instance,
attribute/method-id) gating + DLMS HLS authentication path
needed.

## REPL commands (planned)
- See the generic REPL framework. Expose AssociationInfo (src
  wPort, dst wPort, APDU length, AARE result code).

## Proxy hooks
Wire-layer write-ban: reads wrapper header + APDU body, replies
with a 16-byte wrapper-framed AARE (0xA2 0x03 0x02 0x01 0x01 =
associate-result rejected-permanent) padded with a BER
end-of-content byte. Does NOT forward to upstream.

## Scoring contribution
factors{protocol_risk:75, exposure:70, auth_state:85, capability:30
(70 on DLMS reply), impact_class:65, cve_exposure:0}.
- protocol_risk 75: smart meters with kinetic effects (remote
  disconnect breaker) — slightly above pure metering.
- auth_state 85: DLMS supports HLS authentication but unauth
  probes still elicit AARE responses (negotiation phase).
- impact_class 65: billing accuracy + privacy + remote service
  disconnect.

## Sentinel errors (wire package)
- ErrShortFrame: < 9 bytes (wrapper + 1 APDU byte).
- ErrBadWrapperVersion: version != 0x0001.
- ErrLengthMismatch: wrapper Length disagrees with body size.
- ErrNotAARE: APDU first byte != 0x61.
