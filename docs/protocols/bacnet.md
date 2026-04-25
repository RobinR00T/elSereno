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
| Per-object | `--object type=N;instance=M;property=P` | `WriteProperty` (svc 15) only | exact tuple after BER walk | v1.12 |

Other mutating services (10 CreateObject, 11 DeleteObject, 16
WritePropertyMultiple, 17 DeviceCommunicationControl, 20
ReinitializeDevice, 27 LifeSafetyOperation, 7 AtomicWriteFile,
8 AddListElement, 9 RemoveListElement) keep service-only gating
in v1.12; the per-object layer for those services is a v1.13+
follow-up (their request shapes differ).

```sh
elsereno-offensive write bacnet dry-run \
  --target bms.internal:47808 \
  --service-choice 15 --service-choice 20 \
  --object "type=0;instance=42;property=85" \
  --object "type=2;instance=3;property=85" \
  --vault-passphrase-file ~/.elsereno/dev.pp \
  --emit-allow-file /etc/elsereno/bacnet-gate.yaml
```

Refusal is a BACnet `Abort-PDU` with reason `5` (security-error).
YAML keys: `service_choices:`, `objects:` (`{type, instance,
property}`).

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
