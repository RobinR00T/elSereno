---
phase: F4
status: implemented
last-updated: 2026-04-19
token-budget: 1000
protocol-name: hartip
default-port: 5094/tcp+udp
---

# HART-IP

## TL;DR
ElSereno's `hartip` plugin sends a minimal read-only probe on port 5094/tcp+udp
and classifies the response. Full REPL + per-field decoding land
alongside the generic REPL framework; write operations stay behind
`-tags offensive` (F5).

## Spec references
- FieldComm Group TS20085 / IEC 61804-3

## Wire format (summary)
See `internal/protocols/hartip/wire/` for the from-scratch parser.

## Fingerprint strategy
Session Initiate (master type 1, 30000 ms timer: byte-identical to
the client in the CISA capture with the same sequence number); any
HART-IP response header (MsgType 1) confirms. No HART command is
sent; no vendor/product hint is recorded.

## Read operations (default build)
- `probe`: what `scan` invokes.

## Write / dial operations (offensive build tag)
Deferred to F5.

## REPL commands (planned F4 chunk 2)
- See the generic REPL framework.

## Proxy hooks
Default build: write-ban filter. Session-management messages
forward; a TokenPassPDU (an inner HART command) is answered with
status 0x04 "Unsupported command". The gated package
`offensive/write/hartip` is not wired to `proxy listen` (orphan;
open decision in TODO-vNext).

## Scoring contribution
See `internal/protocols/hartip/hartip.go` for the factor defaults.
Generic pattern: protocol_risk 80-90 (ICS control plane),
auth_state 80-95 (most have no native auth), impact_class 60-90
depending on the physical process affected.
