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
- ReinitializeDevice (svc 20) carries a single primitive
  context-tag-0 enumerated for the reinitializedStateOfDevice:
  - `0x09 NN` — primitive context 0, length 1, where NN is the
    8-value ASHRAE 135 §16.4 enum (0..7).
  An optional `[1] password` CharacterString follows; the gate
  ignores it (password authorisation is between the operator
  and the device).
- DeviceCommunicationControl (svc 17) has the structure
  `[0] timeDuration?  [1] enableDisable  [2] password?` per
  ASHRAE 135 §16.1:
  - Optional `[0]` timeDuration — primitive context 0, length
    1..4 (`0x09..0x0C`). The parser skips past the value bytes.
  - Required `[1]` enableDisable — `0x19 NN` where NN is the
    3-value enum (0 enable, 1 disable, 2 disableInitiation).
  - Optional `[2]` password CharacterString — ignored.
  The gate inspects only the enableDisable enum.
- LifeSafetyOperation (svc 27) has the structure
  `[0] requestingProcessIdentifier  [1] requestingSource
   [2] request  [3] objectIdentifier?` per ASHRAE 135 §16.1A:
  - Required `[0]` Unsigned (length 1..4 inline).
  - Required `[1]` CharacterString (length 1..4 inline OR
    extended-length form `0x1D LL` for length 5..253).
  - Required `[2]` ENUMERATED (`0x29 NN` length 1) — the
    BACnetLifeSafetyOperation enum (0..9).
  - Optional `[3]` BACnetObjectIdentifier — ignored at gate
    level (per-object scoping is v1.14+ if asked).
  The gate parser uses a generic `skipContextPrimitiveField`
  helper that walks the inline-length and extended-length
  forms uniformly so future BACnet services with similar
  envelope structures can reuse it.
- AtomicWriteFile (svc 7) leads with an APPLICATION-tagged
  BACnetObjectIdentifier (NOT context-tagged): `0xC4 PP PP PP
  PP` where the 4 bytes are the standard packed
  `(type<<22) | instance` form. The ObjectType MUST be 10
  (File); anything else is malformed and fails closed. After
  the fileIdentifier comes the access specifier CHOICE
  (`[0]` streamAccess or `[1]` recordAccess, both
  CONSTRUCTED) — the gate ignores the access specifier
  entirely (no per-byte-range scoping).
- AddListElement (svc 8) and RemoveListElement (svc 9) share
  the IDENTICAL request shape per ASHRAE 135 §15.1 + §15.2 —
  `[0] objectIdentifier`, `[1] propertyIdentifier`, `[2]
  propertyArrayIndex` (optional), `[3] listOfElements`. The
  first two fields are EXACTLY the WriteProperty prefix, so
  the gate reuses `wire.ParseWriteProperty` to extract the
  (type, instance, property) target — no separate parser
  needed. The same `AllowedListElements` list applies to
  BOTH services; an operator wanting different policy for
  add vs remove must omit one from `--service-choice` (the
  service-level gate fires first).
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
5. **Per-reinit-states** (`--reinit-state N`) — exact enum
   match. Applies to ReinitializeDevice (svc 20) only. The
   8-value enum (0 coldstart, 1 warmstart, 2..6 backup/restore
   lifecycle, 7 activate-changes) has very different blast
   radii — operators typically allow only state 7 during a
   maintenance window and refuse the rest. The password
   (optional [1] CharacterString) is ignored at gate level.
   **Separate list from all other allowlists**: this is a
   service-internal scoping dimension. v1.13 chunk 9.
6. **Per-DCC-states** (`--dcc-state N`) — exact enum match.
   Applies to DeviceCommunicationControl (svc 17) only. The
   3-value enableDisable enum (0 enable, 1 disable, 2
   disableInitiation) — disable silences the device's BACnet
   communications outright; disableInitiation lets reads
   succeed but suppresses notifications. Typical operator
   pattern: allow only state 0 (recovery direction) and refuse
   1/2 to prevent device silencing. The optional timeDuration
   ([0]) and password ([2]) fields are ignored at gate level.
   v1.13 chunk 10.
7. **Per-LSO-operations** (`--lso-op N`) — exact enum match.
   Applies to LifeSafetyOperation (svc 27) only. The 10-value
   BACnetLifeSafetyOperation enum has very different SAFETY
   blast radii: 1/2/3 silence variants can be LETHAL on
   fire-alarm panels (silencing a panel during an active
   incident); 4/5/6 reset variants clear alarm/fault state;
   7/8/9 unsilence variants are the SAFE recovery direction.
   Operators on production life-safety buses typically allow
   7/8/9 freely + 4/5/6 case-by-case + REFUSE 1/2/3 outright.
   The requestingProcessIdentifier ([0]), requestingSource
   ([1]), and optional objectIdentifier ([3]) fields are all
   ignored at gate level. v1.13 chunk 11.
8. **Per-AWF-files** (`--awf-file N`) — exact File instance
   match. Applies to AtomicWriteFile (svc 7) only. The
   fileIdentifier in the request MUST have ObjectType=10
   (File); anything else fails closed. The access specifier
   (stream vs record + offsets) is ignored at gate level.
   Useful for distinguishing destructive overwrites: when
   File#1 is the device firmware blob and File#5 is a log,
   allow only File#5. v1.13 chunk 12.
9. **Per-list-elements** (`--list-element type=N;instance=M;
   property=P`) — exact (type, instance, property) tuple
   match. Applies to BOTH AddListElement (svc 8) AND
   RemoveListElement (svc 9). Same shape as `AllowedObjects`
   (svc 15/16) but a SEPARATE list — property writes don't
   auto-grant list-mutations. The two services share an
   identical wire prefix so we reuse `wire.ParseWriteProperty`
   for the parser. Common targets: NotificationClass#N.
   recipient_list (102), Schedule#N.exception_schedule (38).
   v1.13 chunk 13 — closes the last BACnet mutating service.

Chunk 10 introduced the `Allowlists` bundle struct (was
`BACnetAllowlists` before linter caught the package stutter):
collects every per-service dimension into a single arg so the
chunk-10+ hash + mutation factories don't need to grow function
parameters every cycle. The pre-existing chunk-1..9 functions
retain their per-dimension signatures for backwards-compat with
operator code that constructs sessions piecewise.

**v1.13 closes every BACnet mutating service.** The full set
covered: svc 7 AtomicWriteFile (chunk 12), svc 8 AddListElement
+ svc 9 RemoveListElement (chunk 13), svc 10 CreateObject
(chunk 8), svc 11 DeleteObject (chunk 7), svc 15 WriteProperty
(v1.12 chunk 7), svc 16 WritePropertyMultiple (chunk 3), svc
17 DeviceCommunicationControl (chunk 10), svc 20
ReinitializeDevice (chunk 9), svc 27 LifeSafetyOperation
(chunk 11). All 9 mutating services have wire-level per-
target-or-state allowlists.

Refusal: BVLC-wrapped Abort-PDU with reason 5 (security-error).

Hash ladder (`AllowlistHashWithListElements` →
`AllowlistHashWithAWF` → `AllowlistHashWithLSOOps` →
`AllowlistHashWithDCCStates` → `AllowlistHashWithReinitStates`
→ `AllowlistHashWithCreateObjects` →
`AllowlistHashWithDeleteObjects` → `AllowlistHashWithObjects`
→ `AllowlistHash`): each successive empty dimension degrades
to the prior-version hash. Separators: 0xF8 (list elements),
0xF9 (AWF files), 0xFA (LSO ops), 0xFB (DCC states), 0xFC
(reinit states), 0xFD (creates), 0xFE (deletes), 0xFF (per-
property objects). Operator confirm-tokens minted before
v1.12 / v1.13 stay valid.

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
