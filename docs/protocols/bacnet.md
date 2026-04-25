# BACnet/IP (UDP 47808)

BACnet (ASHRAE 135) is the dominant Building Automation Systems
(BAS) protocol. HVAC, lighting, fire-alarm, and elevator controllers
speak it — every one is a potential life-safety surface.

## Probe

- Send a BVLC "Original-Broadcast-NPDU" carrying an APDU Who-Is
  (Unconfirmed-Request 0x08, ServiceChoice 0x08) to UDP/47808.
- Parse I-Am responses for Object Identifier + Vendor Identifier +
  Max APDU Length.

BACnet is **UDP** — the usual TCP proxy framework does not apply.

## Proxy policy (default build)

Fail-closed. The TCP proxy framework cannot legitimately relay UDP
BACnet traffic. `bacnet.ProxyHandler()` returns an immediate error
("BACnet proxy requires the offensive UDP relay"). A dedicated UDP
relay lands with the offensive-build WriteProperty deployment.

## Writes (`-tags offensive`)

`offensive/write/bacnet` implements WriteProperty (confirmed service
0x0F) with:

- 10-bit object type + 22-bit instance encoded into the 4-byte
  Object Identifier.
- 1- or 2-byte Property Identifier (context tag 1).
- Caller-supplied pre-encoded Value (context tag 3 opening +
  application-tagged value + closing). The caller is responsible
  for encoding BACnet's primitive tags; helper tooling lives in
  `internal/protocols/bacnet/` (wire tooling lands with F6+).

Object types included: AnalogValue (2), BinaryValue (5),
MultiStateValue (19), Device (8).

### Gated UDP relay (v1.4+)

Two layers of allowlist:

| Layer | Flag | Applies to | Match | Since |
|-------|------|------------|-------|-------|
| Service-choice | `--service-choice 15` | every confirmed-request | exact byte | v1.4 |
| Per-object | `--object type=N;instance=M;property=P` | `WriteProperty` (svc 15, v1.12+) AND `WritePropertyMultiple` (svc 16, v1.13+) | exact tuple after BER walk | v1.12 / v1.13 |
| Per-target-delete | `--delete-object type=N;instance=M` | `DeleteObject` (svc 11) | exact (type, instance) — no property dimension | v1.13 |
| Per-create-type | `--create-object-type N` | `CreateObject` (svc 10) | type-only after BER walk (instance ignored) | v1.13 |
| Per-reinit-state | `--reinit-state N` | `ReinitializeDevice` (svc 20) | exact enum value (0..7 per ASHRAE 135 §16.4) | v1.13 |
| Per-DCC-state | `--dcc-state N` | `DeviceCommunicationControl` (svc 17) | exact enableDisable enum value (0..2 per ASHRAE 135 §16.1) | v1.13 |

The per-object check on **WritePropertyMultiple** walks every
`(ObjectIdentifier, PropertyIdentifier)` pair in the
`listOfWriteAccessSpecifications`. Any single forbidden tuple
refuses the WHOLE WPM batch (fail-closed multi-target gate
analogous to the OPC UA WriteRequest walker).

**AllowedObjects vs AllowedDeleteObjects vs AllowedCreateObjects**
are kept separate by design:

- Property writes (`--object`) don't auto-grant deletion.
- Property writes (`--object`) don't auto-grant creation.
- Deletion (`--delete-object`) doesn't auto-grant creation.

An operator who allowed `--object type=2;instance=99;property=85`
(write PresentValue on BinaryOutput#99) must explicitly add
`--delete-object type=2;instance=99` to permit deletion of that
object, and `--create-object-type 2` to permit creation of
new BinaryOutputs. This matches the typical BAS pattern: most
operators want property writes only, with delete + create
forbidden.

CreateObject is gated **by type only** — even when the operator
uses the BACnet `[1] objectIdentifier` choice form (which
encodes a specific instance), the gate matches by type. Most
CreateObject calls use the `[0] objectType` form where the
device picks the instance, so per-instance gating wouldn't be
useful in practice; operators who need it can ask for v1.14+.

**ReinitializeDevice (svc 20)** is gated **per-state**: the
8-value enum has very different blast radii (0 coldstart wipes
runtime state; 1 warmstart restarts the BACnet stack; 2..6 are
backup/restore lifecycle states; 7 activate-changes is usually
safe). Operators typically allow only state 7 during a
maintenance window. The password (optional context-1
CharacterString in the request) is ignored at gate level —
it's between the operator and the device's password policy.

**DeviceCommunicationControl (svc 17)** is gated **per-state**
across the 3-value enableDisable enum: 0 enable (SAFE — undoes
a prior silence), 1 disable (HOSTILE — blocks all monitoring +
alarms during an incident), 2 disableInitiation (SUBTLER attack
— device responds to polls but won't initiate notifications).
Operators typically allow only state 0 (recovery-from-silence
direction) and refuse 1/2 to prevent device silencing. The
optional timeDuration ([0]) and password ([2]) fields are
ignored at gate level.

Other mutating services (27 LifeSafetyOperation, 7
AtomicWriteFile, 8 AddListElement, 9 RemoveListElement) keep
service-only gating in v1.13; per-object layers for those
services are v1.14+ follow-ups (their request shapes differ).

```sh
elsereno-offensive write bacnet dry-run \
  --target bms.internal:47808 \
  --service-choice 10 --service-choice 11 --service-choice 15 \
  --service-choice 17 --service-choice 20 \
  --object "type=0;instance=42;property=85" \
  --object "type=2;instance=3;property=85" \
  --delete-object "type=2;instance=99" \
  --create-object-type 17 \
  --reinit-state 7 \
  --dcc-state 0 \
  --vault-passphrase-file ~/.elsereno/dev.pp \
  --emit-allow-file /etc/elsereno/bacnet-gate.yaml
```

Refusal is a BACnet `Abort-PDU` with reason `5` (security-error).
YAML keys: `service_choices:`, `objects:` (`{type, instance,
property}`), `delete_objects:` (`{type, instance}`),
`create_object_types:` (`{type}`), `reinit_states:` (uint8 list),
`dcc_states:` (uint8 list).

## Scope

- BAS actuators (AnalogOutput, BinaryOutput) — direct physical
  effect.
- Schedules (Schedule object) — can force occupied / unoccupied
  modes outside working hours.
- Notification Class + Recipient List — writing these silences
  alerts.

## Public references

- ASHRAE Std 135-2020 BACnet.
- NIST IR 7628 (Smart Grid security) §BACnet risks.
