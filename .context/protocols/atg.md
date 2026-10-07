---
phase: F4
status: implemented
last-updated: 2026-04-19
token-budget: 1000
protocol-name: atg
default-port: 10001/tcp
---

# ATG Veeder-Root (TLS-350/4)

## TL;DR
ElSereno's `atg` plugin sends a minimal read-only probe on port 10001/tcp
and classifies the response. Full REPL + per-field decoding land
alongside the generic REPL framework; write operations stay behind
`-tags offensive` (F5).

## Spec references
- Veeder-Root ATG protocol (proprietary)

## Wire format (summary)
No wire package: the probe and the substring classifier live in
`internal/protocols/atg/atg.go`.

## Fingerprint strategy
Send `\x01I20100\n` (the Veeder-Root in-tank inventory query, as
nmap's atg-info.nse). The reply counts as ATG when it contains
"I20100", "IN-TANK" or "VEEDER" anywhere and is not a reflected copy of
the query. No field (station, tanks, volumes) is extracted.

## Read operations (default build)
- `probe`: what `scan` invokes.

## Write / dial operations (offensive build tag)
Deferred to F5.

## REPL commands (planned F4 chunk 2)
- See the generic REPL framework.

## Proxy hooks
Default build: write-ban filter. Only `I`-prefixed (inquiry)
commands forward; any other command (V setpoint, S configuration, T
calibration...) is refused. The gated package `offensive/write/atg` is
not wired to `proxy listen` (orphan; open decision in TODO-vNext).

## Scoring contribution
See `internal/protocols/atg/atg.go` for the factor defaults.
Generic pattern: protocol_risk 80-90 (ICS control plane),
auth_state 80-95 (most have no native auth), impact_class 60-90
depending on the physical process affected.
