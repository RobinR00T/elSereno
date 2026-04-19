---
phase: F2-F4 (planned)
status: draft
last-updated: 2026-04-19
token-budget: 1500
protocol-name: enip
default-port: 44818/tcp + 2222/udp
---

# EtherNet/IP (CIP)

## TL;DR
Placeholder for F0. Fingerprint, REPL, proxy, and scoring details are
filled in when the plugin is implemented. See the project brief (sections
4, 7) and the scoring document for the factors this protocol contributes.

## Spec references
- Primary: ODVA CIP Vol 2, Vol 7
- Secondary: TBD.

## Wire format (summary)
TBD — implementation will include a dedicated `wire/` package under
`internal/protocols/enip/`.

## Fingerprint strategy
TBD.

## Read operations (default build)
- TBD.

## Write / dial operations (offensive build tag)
- TBD.

## REPL commands
- TBD.

## Proxy hooks
TBD.

## Known quirks / vendor deltas
- TBD.

## Test vectors
- `testdata/enip/benign/`
- `testdata/enip/malicious/` (CVE if any)

## Scoring contribution
TBD.

## Open questions
- TBD.
