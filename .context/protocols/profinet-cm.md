---
phase: F4
status: implemented
last-updated: 2026-10-27
token-budget: 1000
protocol-name: profinet-cm
default-port: none (opt-in; UDP 34964)
---

# PROFINET Context Manager (PROFINET-CM)

## TL;DR
`profinet-cm` is an opt-in, read-only probe for PROFINET IO devices. It
sends a DCE/RPC connectionless (v4) endpoint-mapper lookup to UDP 34964
and classifies the reply (device type, order ID, HW/SW revision). The
request matches Nmap's `profinet-cm-lookup.nse` byte for byte. It is
spec-grounded, not yet validated against a real capture.

## Spec references
- DCE/RPC 1.1 connectionless (CL) protocol, packet type Request (0),
  v4 header.
- PROFINET IO (IEC 61158 / IEC 61784) Context Manager interface
  `dea00001-6c97-11d1-8271-00a02442df7d`; EPM interface
  `e1af8308-...`.
- Nmap `profinet-cm-lookup.nse` as the reference request.

## Wire format (summary)
See `internal/protocols/profinetcm/wire/`. `BuildLookup(activity [16]byte)`
builds the 156-byte CL Request with a caller-supplied activity UUID so
the reply can be matched to the request. `Classify(b, activity)` checks
the response is a CL Response (type 2) for our activity UUID and parses
the EPM tower entries into `Reply{PType, Annotation, DeviceType,
OrderID, HWRevision, SWRevision}`.

## Fingerprint strategy
Unconnected UDP socket. A CL Response carrying our activity UUID scores
as PROFINET-CM; anything else (wrong type, wrong activity, short) does
not. The activity UUID comes from `crypto/rand` per probe, so a stray
or replayed datagram cannot be mistaken for our answer.

## Scoring factors
protocol_risk and impact_class reflect an exposed PROFINET IO device;
capability rises when the EPM reply yields order ID / revisions. No auth
on the lookup.

## Safety / read-only posture
A lookup only: no connect, no AR establishment, no write. Fail-closed
proxy (UDP).

## Validation
Spec-grounded. The request is byte-identical to the Nmap script
(regenerated from the `.nse` bytes after an early constant typo). No
public PROFINET-CM lookup capture was found to validate the response
parser against real bytes; marked "spec-grounded, not capture-validated"
in `docs/parser-validation.md` and the protocol table. Fuzz test on the
classifier.
