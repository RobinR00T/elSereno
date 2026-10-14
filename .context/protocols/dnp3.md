---
phase: F4
status: implemented
last-updated: 2026-10-14
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
Request Link Status (link layer only, control 0xC9) to destinations
0..100 from address 0 in one write, byte-identical to nmap's
`dnp3-info.nse`; a reply counts only if its link header CRC is valid.
Until 2026-10-07 the probe sent a zero-CRC header that real outstations
discard (PITF-073).

## Read operations (default build)
- `probe`: what `scan` invokes.

## Write / dial operations (offensive build tag)
Wired 2026-09-22 (`write dnp3 proxy-dry-run` + `proxy listen --plugin
dnp3`). Four-layer gate in `offensive/write/dnp3`, all bound into the
confirm-token via `AllowlistHash(target, Allowlist{...})`:
1. link-layer primary FC (`--dnp3-primary`, optional, 3 or 4 only).
2. destination link address: broadcast `0xFFFD-0xFFFF` mutating frames
   always refused (`wire.IsBroadcast`).
3. application-layer FC (`--dnp3-app-fc`); Read (0x01) always passes.
4. CROB g12v1 scope (`--dnp3-control index=A-B;code=X,Y`): every
   `(index, control-code)` in an Operate / Direct Operate must match;
   `wire.ExtractControlObjects` walks every object header, parses g12v1
   qualifiers 0x17/0x28/0x00/0x01 and fails closed on truncation, an
   unsupported qualifier or left-over octets.
5. Analog Output g41 scope (`--dnp3-analog index=A-B;min=X;max=Y`):
   every setpoint must match a `(index-range, value-window)`; the same
   walker parses g41 var 1-4 (int16/int32/float32/float64), widens the
   value to float64, and fails closed on truncation / unsupported
   variation. `allowsControlObjects` checks every CROB and setpoint of
   every header; any other object type under scoping is refused.
   (`ExtractCROBs` and `ExtractAnalogOutputs` read only the first
   header: the simulator logs with the first, only tests call the
   second.)
The gate judges the whole request: `wire.ExtractControlObjects` walks
every object header (any unscoped type, malformed header or left-over
octet refuses), and multi-segment requests are held until FIN, then
forwarded or refused together (cap 2048 application octets; orphan,
out-of-sequence or other-address-pair continuations discarded). Only a
Read may span segments: the outstation's link layer may drop a segment
the gate forwarded, and two requests could then join into one never
judged (audit, 14-10). Until 2026-10-14 it read only the
first header and judged each frame alone, so a TRIP in a second header
or a second segment passed (PITF-082). The IIN monitor inspects only
first segments.
`--dnp3-link src=N;dest=M` pins the master->outstation pair. Refusal is
a well-formed response with IIN2.0 FUNC_NOT_SUPP (`IIN2` 0x01), the
request's application SEQ and correct CRCs, sent only where an
outstation would answer: a refused broadcast, NO-ACK request
(`wire.AppExpectsNoResponse`), application Confirm, message with UNS
set or fragment without an application header gets nothing (until 2026-10-14: `IIN2` 0x04,
which is IIN2.2 parameter error, SEQ 0, and a reply to every refused
request; PITF-083). Whether to forward Confirms is an open decision.

The forwarder reads the full block-CRC-framed body (`wire.BodyLen` +
`wire.StripBlockCRCs`), not just `Length-5` octets, so real user-data
frames are framed correctly; a bad block CRC is discarded without a
reply (it was answered with a refusal until 2026-10-14). CRC is
CRC-16/DNP (poly 0x3D65, reflected, xorout 0xFFFF; check "123456789" =
0xEA82) in `wire.CRC16`.

## REPL commands (planned F4 chunk 2)
- See the generic REPL framework.

## Proxy hooks
Both builds first apply the stateless rows of AN2013-004b Table 1
(`wire.ReadFrame` + `wire.CheckToOutstation`): an invalid header (start
octets, LENGTH, CRC) is skipped octet by octet until the next valid one
(resync, as the note prescribes); an invalid control combination, data on a frame that
must be header-only, user data without data, reserved destination
`0xFFF0-0xFFFB`, non-user-data to broadcast, reserved source
`0xFFF0-0xFFFF` or a bad block CRC is discarded without a reply (the
offensive gate logs it). Until 2026-10-14 both forwarded any PRM=0
frame and link FC 2/9 (the gate also 0) with their body, so an app request inside one
crossed the write-ban and skipped the gate's four layers (PITF-081).
Default build: write-ban (forwards only Test Link, Request Link Status
and the master's header-only link replies; everything else gets an FC 15
refusal with a correct CRC). Offensive build: the four-layer write-gate above, plus a
response-path IIN monitor (`offensive/write/dnp3/iinmonitor.go`,
`wire.ParseIIN`/`IINStateChange`/`IINError`/`IINBits`): the return
path is parsed (verbatim-forward-first, fail-open on desync) and raises
a `state_change` alert on Device Restart/Trouble/Config-Corrupt (a run
of identical ones de-dups to one) and one `error_burst` on a run of
FUNC_NOT_SUPP/Object-unknown/Parameter-error (default threshold 3).
Alerts log to stderr AND land in the tamper-evident audit chain as a
`dnp3_iin_alert` row (event_type added in migration 00005, enum
`EventDNP3IINAlert`, emitted from `cmd/elsereno/dnp3_iin_audit_offensive.go`
via `rt.Writer`, best-effort); `WriteGatedHandler.OnIIN` overrides.
Demo: `scripts/demo-dnp3-proxy.sh` (`-iin restart`) shows the log line,
the audit row and `audit verify-file` OK.

## Scoring contribution
See `internal/protocols/dnp3/dnp3.go` for the factor defaults.
Generic pattern: protocol_risk 80-90 (ICS control plane),
auth_state 80-95 (most have no native auth), impact_class 60-90
depending on the physical process affected.
