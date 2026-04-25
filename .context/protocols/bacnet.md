---
phase: v1.13-in-flight
status: implemented + per-target gates v1.12/v1.13
last-updated: 2026-04-25
token-budget: 1000
protocol-name: bacnet
default-port: 47808/udp
---

# BACnet/IP

## TL;DR
ElSereno's `bacnet` plugin sends a minimal Who-Is probe on port
47808/udp and classifies I-Am responses. The offensive build adds
a UDP write-gate with per-service-choice + per-(ObjectType,
Instance, PropertyID) tuples for WriteProperty (svc 15, v1.12) +
WritePropertyMultiple (svc 16, v1.13) + per-(ObjectType, Instance)
for DeleteObject (svc 11, v1.13).

## Spec references
- ASHRAE 135 / ISO 16484-5
- ASHRAE 135 §20 (BACnet APDU)
- ASHRAE 135 §21 (BACnet ASN.1 encoding)

## Wire format (summary)
See `internal/protocols/bacnet/wire/` for the from-scratch parser.

ASN.1 BER encoding particulars used by the per-object gate:

- Context tag bytes carry L/V bits in the low nibble:
  - 0..4 = inline length (e.g. tag 1 with L=2 is `0x1A` for
    primitive PropertyId 1..255, which fits into 1-2 bytes).
  - 5 = extended length (length byte follows in the next octet).
  - 6 = OPENING constructed.
  - 7 = CLOSING constructed.
- ObjectIdentifier: tag `0x0C` + 4-byte packed value, where
  `(uint32 >> 22) & 0x3FF` is the 10-bit ObjectType and
  `uint32 & 0x3FFFFF` is the 22-bit ObjectInstance.
- PropertyId in WriteProperty (svc 15) uses CONTEXT TAG 1
  (0x19/0x1A/0x1B for length 1/2/3).
- PropertyId in WritePropertyMultiple (svc 16) inner
  BACnetPropertyValue uses CONTEXT TAG 0 (0x09/0x0A/0x0B).
- CreateObject (svc 10) wraps its objectSpecifier in a
  CONSTRUCTED context tag 0 (0x0E open / 0x0F close). The
  inner CHOICE is one of:
  - `0x09 TT` — `[0] objectType`, primitive, length 1 (type ≤ 255).
  - `0x0A TT TT` — `[0] objectType`, primitive, length 2 (type 256..1023).
  - `0x1C PP PP PP PP` — `[1] objectIdentifier`, primitive, length 4
    (BACnetObjectIdentifier packed as `(type<<22) | instance`).
  Optional `[1] listOfInitialValues` follows after the close tag.
- WPM SEQUENCE-OF-WriteAccessSpecification structure:
  ```
  SEQUENCE {
    objectIdentifier  [0]  BACnetObjectIdentifier
    listOfProperties  [1]  SEQUENCE OF BACnetPropertyValue
  }
  ```
  where each BACnetPropertyValue has CONSTRUCTED inner values
  (BACnetWeeklySchedule, BACnetDateRange, …) — the walker is
  depth-aware via `skipUntilDepthZero` / `skipOneTagBody`.

## Fingerprint strategy
One-shot Who-Is probe to UDP/47808; classify I-Am responses by
Object Identifier + Vendor Identifier + Max APDU Length.

## Read operations (default build)
- `probe`: what `scan` invokes.

## Write / dial operations (offensive build tag)

Three layers of allowlist (cumulative):

1. **Service-choice** (`--service-choice 15`) — exact byte match
   against the confirmed-request choice. v1.4 chunk 6.
2. **Per-property objects** (`--object type=N;instance=M;
   property=P`) — exact tuple match after BER walk. Applies to:
   - WriteProperty (svc 15) — v1.12 chunk 7.
   - WritePropertyMultiple (svc 16) — v1.13 chunk 3. Walks
     EVERY (ObjectIdentifier, PropertyIdentifier) pair in the
     listOfWriteAccessSpecifications. ANY single forbidden
     tuple refuses the WHOLE WPM batch (fail-closed, analogous
     to the OPC UA WriteRequest walker).
3. **Per-target deletes** (`--delete-object type=N;instance=M`)
   — exact (ObjectType, ObjectInstance) match. Applies to
   DeleteObject (svc 11) only. **Separate list from
   AllowedObjects** — the typical BAS pattern is "writes ok,
   delete forbidden", so an operator who allowed
   `--object type=2;instance=99;property=85` MUST add
   `--delete-object type=2;instance=99` to permit deletion.
   v1.13 chunk 7.
4. **Per-create-types** (`--create-object-type N`) — type-only
   match (instance ignored even when the [1] choice form
   encodes one). Applies to CreateObject (svc 10) only.
   **Separate list from both AllowedObjects and
   AllowedDeleteObjects** — property writes don't auto-grant
   creation; deletion privileges don't auto-grant creation.
   The typical BAS use-case is "operator may create new
   Schedule objects on this device" — type-level allowlist
   matches naturally; per-(type, instance) Create
   allowlisting is rare since the device usually picks the
   instance. v1.13 chunk 8.

Other mutating services (svc 17 DeviceCommunicationControl,
svc 20 ReinitializeDevice, svc 27 LifeSafetyOperation, svc 7
AtomicWriteFile, svc 8/9 Add/RemoveListElement) keep
service-only gating; per-object layers for those services are
v1.14+ follow-ups (their request shapes differ).

Refusal: BVLC-wrapped Abort-PDU with reason 5 (security-error).

Hash ladder (`AllowlistHashWithCreateObjects` →
`AllowlistHashWithDeleteObjects` → `AllowlistHashWithObjects` →
`AllowlistHash`): each successive empty dimension degrades to
the prior-version hash. Separators: 0xFD (creates), 0xFE
(deletes), 0xFF (per-property objects). Operator confirm-tokens
minted before v1.12 / v1.13 stay valid.

## REPL commands (planned F4 chunk 2)
- See the generic REPL framework.

## Proxy hooks
Default-build refuses with the abort-PDU. Offensive build
routes via `WriteGatedHandler.routeFrame` →
`perObjectGatesAllow` (extracted in v1.13 chunk 7 for gocyclo
hygiene).

## Scoring contribution
See `internal/protocols/bacnet/bacnet.go` for the factor defaults.
Generic pattern: protocol_risk 80-90 (ICS control plane),
auth_state 80-95 (most have no native auth), impact_class 60-90
depending on the physical process affected.
