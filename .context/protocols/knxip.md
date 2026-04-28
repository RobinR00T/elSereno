---
phase: v1.21
status: implemented
last-updated: 2026-04-28
token-budget: 900
protocol-name: knxip
default-port: 3671/udp
---

# KNXnet/IP

## TL;DR
ElSereno's `knxip` plugin sends a 14-byte DESCRIPTION_REQUEST
(service type 0x0204) on UDP/3671 with a control HPAI of
0.0.0.0:0 and folds the parsed 30-byte ASCII Friendly Name +
KNX Medium + KNX Individual Address into the finding hash.
v1.21 chunk 1 ships read-only fingerprint plus a fail-closed
ProxyHandler (TCP framework can't relay UDP).

## Spec references
- KNX Standard 03.08.02 (Core) — KNXnet/IP services.
- KNX Standard 03.08.03 (Routing) — multicast routing.
- KNX Standard 03.06.03 (EMI) — group addresses + DPT.

## Wire format (summary)
14-byte request, 60-byte success response. Frame layout in
`internal/protocols/knxip/wire/wire.go`:

Request: `06 10 02 04 00 0E 08 01 00 00 00 00 00 00`
Response: header (6 bytes) + Device Hardware DIB (54 bytes)
where bytes [30..60) are the 30-byte ASCII friendly name.

KNX Medium values: 0x02=TP1 (twisted-pair, dominant), 0x04=PL110
(power-line), 0x10=RF, 0x20=IP.

## Fingerprint strategy
One-shot probe over UDP. The friendly name string ("MDT IP
Interface", "Gira Standard", "Jung KNX/IP", etc.) is the
canonical signal — captured into the finding hash so dedup is
per-device-name. Sentinel-error classification surfaces in the
note: short frame, bad header, wrong service type, length
disagreement, missing device-info DIB.

## Read operations (default build)
- `probe`: dials UDP/3671, sends BuildDescriptionRequest, reads
  up to 1500 bytes, parses with ParseDescriptionResponse.

## Write / dial operations (offensive build tag)
Deferred. KNXnet/IP supports CONNECT_REQUEST (0x0205),
TUNNELLING_REQUEST (0x0420 — write group address values),
DEVICE_CONFIGURATION_REQUEST (0x0310), ROUTING_INDICATION
(0x0530 multicast). Each needs per-(group address, service type)
allowlist gating. Triple-confirm + audit-chain emission per
ADR-009. KNX/IP Secure (2018+) is an optional encrypted layer.

## REPL commands (planned)
- See the generic REPL framework. Expose DeviceInfo fields
  read-only (Friendly Name, Medium, Individual Address, Project
  Installation ID, Serial Number, Multicast Address, MAC
  Address).

## Proxy hooks
Fail-closed: TCP proxy framework cannot legitimately relay UDP
KNXnet/IP frames. ProxyHandler.Handle() returns immediately
with an error citing the missing UDP relay. Mirrors the BACnet
+ KNX UDP-protocol pattern.

## Scoring contribution
factors{protocol_risk:75, exposure:75, auth_state:90, capability:30
(75 on KNX reply), impact_class:70, cve_exposure:0}.
- protocol_risk 75 (vs 80 for industrial PLCs) reflects BAS focus
  rather than direct factory-floor control.
- auth_state 90 (vs 95) because KNX/IP Secure exists as an
  optional layer though most deployments don't enable it.
- impact_class 70 reflects BAS blast radius (HVAC, lighting,
  blinds, access control, life-safety adjacent).

## Sentinel errors (wire package)
- ErrShortFrame: < 60-byte response.
- ErrBadHeader: header bytes not 0x06 0x10.
- ErrNotResponse: service type not 0x0205.
- ErrLengthMismatch: TotalLength field disagrees with buffer.
- ErrMissingDeviceInfoDIB: DIB type at offset 7 != 0x01.

These surface to the operator-facing note via `classifyParseError`
(plugin layer).
