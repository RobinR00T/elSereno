# Red Lion Crimson / RLN (TCP 789)

Red Lion Controls is an HMI / RTU vendor whose product family
includes G3, G3 Kadet, Graphite, FlexEdge, DA-50N, and the
post-2010-acquisition Sixnet RTU line. Crimson 3 is the
proprietary firmware / IDE; RLN (Red Lion Net) is the wire
protocol on TCP/789. Many devices also expose 23 (telnet) and
80 (HTTP) for the same controller.

## Probe

- Connect to TCP/789. RLN servers typically send an unsolicited
  banner on connect.
- If no banner arrives within IOTimeout/2, send a 3-byte zero
  hello (`0x00 0x00 0x00`) — most Crimson firmware ignores
  zero-padded handshakes and replies with the default banner.
- Classify the response by canonical Red Lion banner substring:
  `Red Lion Controls`, `Red Lion`, `Crimson 3`, `CRIMSON 3`,
  `Crimson 2`, `FlexEdge`, `Graphite`, `DA-50N`, `DA50N`,
  `G3 Kadet`, `G3 HMI`, `Sixnet`.

The banner-substring approach is the conservative public-data
choice — Crimson 3's tag-length-value RLN frame layout is not
fully published, but every Internet-exposed device announces
itself via banner.

## Wire layout

RLN frames use a 3-byte handshake plus tag-length-value bodies.
This plugin only inspects the banner text (which is plain ASCII)
and does not parse RLN TLV frames.

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
