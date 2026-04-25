# IAX2 (Inter-Asterisk eXchange v2)

**Default port**: 4569/udp.
**Status**: probe + write-gated proxy.
**Offensive build**: per-subclass allowlist (NEW / REGREQ /
AUTHREP / ACCEPT and the rest of RFC 5456 control subclasses).

## Probe

Sends a minimal `NEW` (subclass 0x01) with a synthetic
`SrcCallNum`. Classifies the response: `ACCEPT` (subclass 0x02)
/ `AUTHREQ` (0x06) / `REJECT` (0x05) / `INVAL` (0x0A) / silence.
RFC 5456 full-frame parser; the binary protocol is
length-prefixed UDP, so each datagram carries one frame.

## Default-build refusal posture

The default proxy responds with an IAX2 `HANGUP` frame (subclass
0x05) addressed to the client's `SrcCallNum` for any non-allowed
subclass. Mini-frames (audio) and non-IAX full frames (Voice /
DTMF / Video / etc.) ALWAYS pass — media is never blocked.

Always-safe subclasses (never gated): `HANGUP`, `ACK`, `PING`,
`PONG`, `LAGRQ`, `LAGRP`, `INVAL`, `REGAUTH`, `REGACK`, `REGREJ`,
`REGREL`, `REJECT`.

## Offensive write-gate

```sh
elsereno-offensive write iax2 dry-run \
  --target pbx.internal:4569 \
  --subclass NEW --subclass REGREQ \
  --vault-passphrase-file ~/.elsereno/dev.pp \
  --emit-allow-file /etc/elsereno/iax2-gate.yaml
```

YAML: `subclasses: [NEW, REGREQ, AUTHREP, ACCEPT]`.

## See also

- `.context/protocols/iax2.md` for the wire-level RFC 5456 notes.
- ADR-040 for the write-gate template.
