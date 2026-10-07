# IAX2 (Inter-Asterisk eXchange v2)

**Default port**: 4569/udp.
**Status**: probe + write-gated proxy.
**Offensive build**: per-subclass allowlist (NEW / REGREQ /
AUTHREP / ACCEPT and the rest of RFC 5456 control subclasses).

## Probe

Sends a minimal `NEW` (subclass 0x01, a bare 12-byte full-frame
header, no IEs) with a synthetic `SrcCallNum`. Classifies the
response by RFC 5456 subclass: `ACCEPT` (0x07) / `AUTHREQ` (0x08) /
`REJECT` (0x06) / `INVAL` (0x0A). Silence or an ICMP unreachable still
yields a scored "no-response" finding.
RFC 5456 full-frame parser; the binary protocol is
length-prefixed UDP, so each datagram carries one frame.

## Default-build refusal posture

The default proxy is deny-all: it relays nothing and answers nothing
(UDP has no stream-level refusal). The subclass-aware gate below,
which answers a refused subclass with an IAX2 `HANGUP` (0x05) and
always passes media (mini-frames, Voice / DTMF / Video), is the
offensive build's (`offensive/write/iax2`).

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
