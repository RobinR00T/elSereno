---
phase: F2-F4 (planned)
status: draft
last-updated: 2026-04-19
token-budget: 1500
protocol-name: modbus
default-port: 502/tcp
---

# Modbus/TCP

## TL;DR
Placeholder for F0. Fingerprint, REPL, proxy, and scoring details are
filled in when the plugin is implemented. See the project brief (sections
4, 7) and the scoring document for the factors this protocol contributes.

## Spec references
- Primary: Modbus Application Protocol V1.1b3, Modbus Messaging on TCP/IP V1.0b
- Secondary: TBD.

## Wire format (summary)
TBD — implementation will include a dedicated `wire/` package under
`internal/protocols/modbus/`.

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
- `testdata/modbus/benign/`
- `testdata/modbus/malicious/` (CVE if any)

## Scoring contribution
TBD.

## Open questions
- TBD.
