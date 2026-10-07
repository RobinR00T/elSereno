---
phase: F4
status: implemented
last-updated: 2026-04-19
token-budget: 1000
protocol-name: enip
default-port: 44818/tcp
---

# EtherNet/IP CIP

## TL;DR
ElSereno's `enip` plugin sends a minimal read-only probe on port 44818/tcp
and classifies the response. Full REPL + per-field decoding land
alongside the generic REPL framework; write operations stay behind
`-tags offensive` (F5).

## Spec references
- ODVA CIP Vol 2 (Encapsulation); Vol 7 (IP adaptation)

## Wire format (summary)
See `internal/protocols/enip/wire/` for the from-scratch parser.

## Fingerprint strategy
ListIdentity (24-byte encapsulation header, command 0x0063, empty
body). The reply's identity item (VendorID, DeviceType, ProductName...)
is parsed; ProductName drives the Rockwell CVE lookup (cve.ForENIP).
The identity strings are hashed into the finding ID, not printed.

## Read operations (default build)
- `probe`: what `scan` invokes.

## Write / dial operations (offensive build tag)
Deferred to F5.

## REPL commands (planned F4 chunk 2)
- See the generic REPL framework.

## Proxy hooks
Default build: write-ban handler (encapsulation commands classified;
anything not a read is refused). Offensive build: per-command and
optional per-CIP-object gate (`--cip-command`, `--cip-attr`).

## Scoring contribution
See `internal/protocols/enip/enip.go` for the factor defaults.
Generic pattern: protocol_risk 80-90 (ICS control plane),
auth_state 80-95 (most have no native auth), impact_class 60-90
depending on the physical process affected.
