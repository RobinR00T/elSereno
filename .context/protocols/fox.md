---
phase: F4
status: implemented
last-updated: 2026-04-19
token-budget: 1000
protocol-name: fox
default-port: 1911,4911/tcp
---

# Niagara Fox (Tridium)

## TL;DR
ElSereno's `fox` plugin sends nmap's fox-info client hello on port 1911/tcp
and classifies the response. Full REPL + per-field decoding land
alongside the generic REPL framework; write operations stay behind
`-tags offensive` (F5).

## Spec references
- Tridium Niagara framework (proprietary)

## Wire format (summary)
Line-oriented text: `fox a <0|1> -1 fox <verb>\n{\n<key>=<type>:<value>\n...};;`.
A client's messages start `fox a 1`, a station's `fox a 0`. No wire
package: the probe and classifier live in `internal/protocols/fox/fox.go`.

## Fingerprint strategy
The client speaks first (w3h/icsmaster fox_info.pcap): send
`HelloRequest` (byte for byte nmap's fox-info.nse query), then classify
the reply as a station message when it starts `fox a 0` and carries a
`{` dictionary. Until 2026-10-07 the probe sent nothing and waited, so a
real station never answered (PITF-078).

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
See `internal/protocols/fox/fox.go` for the factor defaults.
Generic pattern: protocol_risk 80-90 (ICS control plane),
auth_state 80-95 (most have no native auth), impact_class 60-90
depending on the physical process affected.
