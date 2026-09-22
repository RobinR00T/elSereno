---
phase: F4
status: implemented
last-updated: 2026-09-22
token-budget: 1000
protocol-name: dnp3
default-port: 20000/tcp
---

# DNP3

## TL;DR
ElSereno's `dnp3` plugin sends a minimal read-only probe on port 20000/tcp
and classifies the response. The offensive build (`-tags offensive`)
adds a four-layer write-gated proxy (app-FC + CROB control-code/index +
broadcast deny + link-address pin), wired to the CLI on 2026-09-22.

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
Wired 2026-09-22 (`write dnp3 proxy-dry-run` + `proxy listen --plugin
dnp3`). Four-layer gate in `offensive/write/dnp3`, all bound into the
confirm-token via `AllowlistHash(target, Allowlist{...})`:
1. link-layer primary FC (`--dnp3-primary`, optional).
2. destination link address: broadcast `0xFFFD-0xFFFF` mutating frames
   always refused (`wire.IsBroadcast`).
3. application-layer FC (`--dnp3-app-fc`); Read (0x01) always passes.
4. CROB g12v1 scope (`--dnp3-control index=A-B;code=X,Y`): every
   `(index, control-code)` in an Operate / Direct Operate must match;
   `wire.ExtractCROBs` parses qualifiers 0x17/0x28/0x00/0x01 and fails
   closed on truncation or an unsupported qualifier.
`--dnp3-link src=N;dest=M` pins the master->outstation pair. Refusal is
a well-formed `IIN2 FUNC_NOT_SUPP` (byte2 0x04) with correct CRCs.

The forwarder reads the full block-CRC-framed body (`wire.BodyLen` +
`wire.StripBlockCRCs`), not just `Length-5` octets, so real user-data
frames are framed correctly; a bad block CRC fails closed. CRC is
CRC-16/DNP (poly 0x3D65, reflected, xorout 0xFFFF; check "123456789" =
0xEA82) in `wire.CRC16`.

## REPL commands (planned F4 chunk 2)
- See the generic REPL framework.

## Proxy hooks
Default build: deny-all (link-layer classify + FC 15 refusal, correct
CRC). Offensive build: the four-layer write-gate above. Demo:
`scripts/demo-dnp3-proxy.sh` against `simulators/dnp3`.

## Scoring contribution
See `internal/protocols/dnp3/dnp3.go` for the factor defaults.
Generic pattern: protocol_risk 80-90 (ICS control plane),
auth_state 80-95 (most have no native auth), impact_class 60-90
depending on the physical process affected.
