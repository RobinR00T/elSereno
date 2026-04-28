# DLMS/COSEM (TCP 4059)

DLMS/COSEM (Device Language Message specification / Companion
Specification for Energy Metering) is the IEC 62056 family of
protocols for smart electricity, gas, water, and heat meters.
TCP/4059 carries the DLMS Wrapper format (IEC 62056-46 §8.4)
that frames the COSEM application-layer APDUs.

## Probe

- Send a 37-byte DLMS-wrapper-framed AARQ (Application
  Association Request) probe: 8-byte wrapper + 29-byte canonical
  minimal AARQ APDU referencing the LN-no-ciphering application
  context (OID 2.16.756.5.8.1.1).
- Read the wrapper header (8 bytes) to learn the declared APDU
  length, then read the body. Classify by:
  - Wrapper version 0x0001 ✓ + AARE tag (0x61) at the APDU
    offset → confirmed DLMS/COSEM server.
  - Wrapper version 0x0001 ✓ but APDU is something other than
    AARE → still positive identification (the server speaks
    DLMS-wrapper but rejected our AARQ; common with HLS-locked
    deployments).

## Wire layout

```
DLMS Wrapper (8 bytes):
  Offset  Field       Size  Description
  0..1    Version     2     0x0001 BE
  2..3    SourceWPort 2     BE — typically 0x0010 (Public Client)
  4..5    DestWPort   2     BE — 0x0001 (Server Mgmt Logical Device)
  6..7    Length      2     BE — APDU length

APDU (BER-encoded COSEM AARQ/AARE):
  AARQ tag:                  0x60  (request)
  AARE tag:                  0x61  (response)
  application-context-name:  [1] EXPLICIT OID
  user-information:          [APPLICATION 30] EXPLICIT OCTET STRING
                                (InitiateRequest / InitiateResponse)
```

## Proxy policy (default build)

Wire-layer write-ban. The default-build handler reads the 8-byte
wrapper header from the client, drains the declared APDU body,
and replies with a 16-byte wrapper-framed AARE (associate-result
rejected-permanent). Does NOT forward to upstream.

## Writes (`-tags offensive`)

Deferred. DLMS/COSEM supports:
- `GET-Request` (read attribute) — typically read-only but some
  attributes are writeable.
- `SET-Request` — write attribute on a COSEM object (e.g.,
  tariff schedule, push-setup destination, billing reset
  parameters).
- `ACTION-Request` — invoke a COSEM method (e.g., disconnect
  control object's `remote_disconnect()` — physically opens the
  service breaker; `reset()` on billing periods).
- `EventNotification-Request` — server-initiated push (less
  attack-relevant since it's read at the client end).

A future offensive plugin would gate per-(class-id, instance,
attribute/method-id) (analogous to OPC UA per-NodeId). DLMS HLS
authentication (low/med/high security suites) needs a parallel
crypto path. Triple-confirm + audit-chain emission per ADR-009.

## Scope

- Smart electricity meters in residential, commercial, and
  industrial deployments across the EU + UK + many APAC
  countries.
- Smart gas meters with DLMS/COSEM gateways.
- AMI (Advanced Metering Infrastructure) head-end systems
  bridging DLMS to billing.
- Impact: a writeable DLMS endpoint can manipulate billing
  registers (consumer fraud / utility loss), invoke
  `remote_disconnect()` (cuts service to the consumer — DoS),
  rewrite tariff schedules (non-trivial billing manipulation),
  or change push-destination URLs (data exfiltration to attacker
  endpoint).

## Public references

- IEC 62056-46: DLMS Wrapper (Green Book §8.4).
- IEC 62056-53: COSEM application layer.
- IEC 62056-62: Interface classes catalogue.
- DLMS UA "Coloured Books" — Blue Book + Green Book +
  White Book (registration required, public via DLMS UA).
- Maxa Bondarenko + Friedrich "DLMS/COSEM security analysis"
  (S4x18, IEEE).
