---
phase: F4
status: implemented
last-updated: 2026-04-19
token-budget: 1000
protocol-name: dnp3
default-port: 20000/tcp
---

# DNP3

## TL;DR
ElSereno's `dnp3` plugin sends a minimal read-only probe on port 20000/tcp
and classifies the response. Full REPL + per-field decoding land
alongside the generic REPL framework; write operations stay behind
`-tags offensive` (F5).

## Spec references
- IEEE 1815 (2012) data link + application

## Wire format (summary)
See `internal/protocols/dnp3/wire/` for the from-scratch parser.

## Fingerprint strategy
One-shot probe: send the smallest valid request the protocol accepts;
classify the response header and record a vendor/product hint when
available.

## Read operations (default build)
- `probe`: what `scan` invokes.

## Write / dial operations (offensive build tag)
Deferred to F5.

## REPL commands (planned F4 chunk 2)
- See the generic REPL framework.

## Proxy hooks
Default pass-through. Write-gating (where it applies) lands in F5 with
the per-FC / per-command matrix.

## Scoring contribution
See `internal/protocols/dnp3/dnp3.go` for the factor defaults.
Generic pattern: protocol_risk 80-90 (ICS control plane),
auth_state 80-95 (most have no native auth), impact_class 60-90
depending on the physical process affected.
