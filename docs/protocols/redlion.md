# Red Lion Crimson v3 (CR3, TCP 789)

Red Lion Controls is an HMI / RTU vendor whose product family
includes G3, G3 Kadet, Graphite, FlexEdge, DA-50N, and the
post-2010-acquisition Sixnet RTU line. Crimson 3 is the
proprietary firmware / IDE; it talks to panels over the Crimson v3
(CR3) protocol on TCP/789. Many devices also expose 23 (telnet) and
80 (HTTP) for the same controller.

## Probe

- Connect to TCP/789 and read the manufacturer register with the
  frame `00 04 01 2B 1B 00`, then (if the panel answered) the model
  register with `00 04 01 2A 1A 00`. Both are byte for byte the
  probes of `cr3-fingerprint.nse` (internetofallthethings/cr3-nmap,
  by the author of the CR3 Wireshark dissector) and of
  praetorian-inc/nerva's crimsonv3 plugin. That README shows a panel
  answering "Red Lion Controls" and "G310C2".
- Classify the reply as a CR3 string response: a length field that
  matches a complete frame, then after the 6-octet header (length,
  register, type) a non-empty printable string (a trailing NUL is
  dropped), answering register 0x012B or naming Red Lion. The model
  reply must answer register 0x012A when the manufacturer reply echoed
  its register; otherwise any CR3 string frame is taken. The note carries `manufacturer=` and
  `model=`.
- Fallback: a canonical banner substring anywhere in the reply
  (`Red Lion Controls`, `Red Lion`, `Crimson 3`, `CRIMSON 3`,
  `Crimson 2`, `FlexEdge`, `Graphite`, `DA-50N`, `DA50N`, `G3 Kadet`,
  `G3 HMI`, `Sixnet`). A reflected copy of our read is rejected.
- Until 2026-10-07 the probe waited for an unsolicited connect banner
  and then sent three zero bytes, claiming panels announce themselves
  and answer zero-padded handshakes; no source supports either, and
  the sources above show the client asks first (PITF-079). Validated
  against those reference implementations, not against a packet
  capture: none is public.

## Wire layout

CR3 frame (cr3-wireshark `cr3.lua`): length (2, big-endian, counts the
bytes after itself), register (2), then the payload, whose first two
octets are a type; the identity registers return a NUL-terminated
string after it. The same framing drives the offensive write-gate
below.

## Proxy policy (default build)

Fail-closed. In the default build the proxy refuses sessions
immediately rather than relay bytes that may or may not be valid
RLN frames. The write-gated relay lives in the offensive build (see
below), where the CR3 length-prefixed framing is parsed
frame-by-frame.

## Writes (`-tags offensive`)

Shipped. The write-gated TCP proxy lives in
`offensive/write/redlion` (TCP/789). CR3 is length-prefixed
(2-byte big-endian body length at offset 0), so the handler reads
discrete frames via `wire.ReadFrame` and gates each by its Type
opcode (at offset 4). Read opcodes (`0x1b00` mem-read, `0x1700`
poll) always pass; a mutating opcode is admitted only when its
Type is allowlisted.

```sh
# 1) Mint the session confirm-token (ADR-039 triple-confirm):
elsereno-offensive write redlion proxy-dry-run \
  --target hmi.internal:789 \
  --redlion-type 0x1500 \          # config/firmware chunk upload
  --redlion-type 0x1300 \          # value write
  --vault-passphrase-file ~/.elsereno/dev.pp

# 2) Run the gated proxy (TCP/789) with the triple-confirm fence:
elsereno-offensive proxy listen --plugin redlion \
  --listen 127.0.0.1:789 --target hmi.internal:789 \
  --redlion-type 0x1500 --redlion-type 0x1300 \
  --accept-writes --confirm-target hmi.internal:789 \
  --confirm-token <token-from-dry-run> \
  --vault-passphrase-file ~/.elsereno/dev.pp
```

Flag: `--redlion-type <u16>` (Crimson v3 Type opcode, decimal or
`0x..`, repeatable; e.g. `0x1500` config/firmware chunk, `0x1300`
value write, `0x0300` register push).

**Conservative classifier (and why)**: the public dissector
(internetofallthethings/cr3-wireshark) is "a minimal dissector, a
starting point": it establishes the framing and enumerates the
Type opcodes but does NOT authoritatively label every opcode
read-vs-write. So the auto-pass set is deliberately narrow (only
opcodes carrying an explicit read-request field structure); the
chunk/value/register-push opcodes are the known writes; every
other opcode (handshake / no-payload included) is refused unless
the operator allowlists it after establishing its semantics in
their own environment. No fabricated semantics.

**Refusal semantics**: CR3 has no documented per-request NAK, so
a refusal **CLOSES the connection** (fail-closed), mirroring the
GE-SRTP handler; the client reconnects and resyncs. The framing +
opcodes come from `internal/protocols/redlion/wire`. Triple-confirm
+ audit-chain emission per ADR-039.

## Scope

- HMIs at oil & gas wellheads, water-treatment plants, packaging
  lines, and discrete-manufacturing factory-floor visualisation
  (Crimson 3 is one of the most common embedded HMI runtimes
  in North-American SCADA).
- Sixnet RTUs at gas-pipeline + electric-substation comms
  bridges.
- Impact: a writeable RLN endpoint can rewrite operator-facing
  HMI screens (display fake values), force tag values that
  drive PID loops, or push a malicious firmware blob.

## Public references

- ICS-CERT advisories ICSA-21-103-01 (Crimson 3.1 hardcoded
  cryptographic key), ICSA-22-088-01 (Crimson 3.1 path
  traversal).
- Shodan dorks: `port:789 redlion`, `port:80 "Red Lion"`.
- Red Lion Crimson 3 product manuals (registration required at
  redlion.net).
