# KNXnet/IP (UDP 3671)

KNXnet/IP is the IP-bridging layer for KNX, the dominant European
Building Automation Systems (BAS) protocol. KNX runs HVAC,
lighting, blinds, access control, and life-safety adjacent
systems in residential + commercial buildings; KNXnet/IP gateways
+ IP-routers are how those L2 KNX networks reach the Internet.

## Probe

- Send the 14-byte KNXnet/IP DESCRIPTION_REQUEST (service type
  0x0204) with a control HPAI of 0.0.0.0:0 (anonymous endpoint).
- Parse the DESCRIPTION_RESPONSE (0x0205): 30-byte ASCII friendly
  name + KNX Medium byte + KNX Individual Address.
- The friendly name folds into the finding hash so dedup is
  per-device-name. KNX Medium decodes as: 0x02=TP1, 0x04=PL110,
  0x10=RF, 0x20=IP.

KNXnet/IP is **UDP** — the usual TCP proxy framework does not
apply.

## Wire layout (DESCRIPTION_REQUEST/RESPONSE)

```
KNXnet/IP header (6 bytes):
  Offset  Field             Value
  0       HeaderLen         0x06
  1       ProtocolVersion   0x10 (KNXnet/IP 1.0)
  2..3    ServiceType       0x0204 (req) / 0x0205 (resp), BE
  4..5    TotalLength       BE

Request body (8 bytes — control HPAI):
  6       HPAILen           0x08
  7       HPAIProtocol      0x01 (UDP)
  8..11   IPv4 address      0.0.0.0
  12..13  Port              0

Response body (54 bytes — Device Hardware DIB):
  6       DIB length        0x36
  7       DIB type          0x01 (Device Hardware)
  8       KNX Medium
  9       Device Status     bit 0 = programming mode
  10..11  KNX Individual Address (BE)
  12..13  Project Installation ID
  14..19  KNX Serial Number
  20..23  Multicast Address (KNXnet/IP routing)
  24..29  KNX MAC Address
  30..59  Friendly name (30 bytes ASCII, NUL-padded)
```

## Proxy policy (default build)

Fail-closed. The TCP proxy framework cannot legitimately relay
UDP KNXnet/IP traffic. `knxip.ProxyHandler()` returns an
immediate error. A dedicated UDP relay would arrive with a future
offensive write plugin (CONNECT/TUNNELLING_REQUEST gating).

## Writes (`-tags offensive`)

Deferred. KNXnet/IP write services include:
- `0x0205` CONNECT_REQUEST (open tunnelling channel)
- `0x0420` TUNNELLING_REQUEST (write group address values —
  light switches, valve actuators, blind motors)
- `0x0310` DEVICE_CONFIGURATION_REQUEST (read/write KNX
  property values on the device's interface object)
- `0x0530` ROUTING_INDICATION (multicast write — KNXnet/IP
  routing mode)

A future offensive plugin would gate per-(group address,
service type) (analogous to BACnet per-(object, property)) and
emit `audit-chain` events per tunnelling request. Triple-confirm
+ audit-chain emission per ADR-009.

KNXnet/IP **Secure** (KNX/IP Secure, 2018+) is an optional
encrypted transport on the same port; ElSereno's offensive layer
would need to support both.

## Scope

- KNX BAS gateways and IP-routers in residential, hotel, and
  commercial buildings.
- Compatible HMIs (Gira, Jung, MDT, ABB, Siemens N148/22, Berker).
- Impact: a writeable KNX endpoint can drive any actuator on the
  KNX bus — turn off building lighting, open all windows, force
  HVAC into dehumidify mode, override fire-door electromagnetic
  locks. KNX is BAS-adjacent to life safety (smoke evacuation
  control, elevator emergency mode).

## Public references

- KNX Standard 03.08.02 (Core) — KNXnet/IP services.
- KNX Standard 03.08.03 (Routing) — multicast routing details.
- KNX Standard 03.06.03 (External Message Interface) — group
  addresses + DPT (Datapoint Type) catalogue.
- ICS-CERT and ICSA advisories on KNXnet/IP devices lacking auth
  (multiple, 2014-onwards).
