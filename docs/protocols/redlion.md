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

Fail-closed. RLN's deeper TLV layers are not implemented in
chunk 3; the default-build proxy refuses sessions immediately
rather than relay bytes that may or may not be valid RLN
frames. A relay arrives with the future offensive plugin.

## Writes (`-tags offensive`)

Deferred. Crimson 3 supports tag manipulation, project
download, password reset, and remote firmware upgrade through
RLN — all of which qualify as kinetic-effect writes on the HMI.
A future offensive plugin would gate per-(RLN command, target
tag/object) and emit `audit-chain` events.

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
