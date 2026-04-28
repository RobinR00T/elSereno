---
phase: v1.20
status: implemented
last-updated: 2026-04-28
token-budget: 1000
protocol-name: slmp
default-port: 5007/tcp
---

# MELSEC SLMP

## TL;DR
ElSereno's `slmp` plugin sends a single READ CPU MODEL NAME 3E-frame
(command 0x0101, subcommand 0x0000) on TCP/5007 and folds the
parsed 16-byte ASCII Model + 2-byte CPU type code into the finding
hash. v1.20 chunk 2 ships read-only fingerprint with a wire-layer
write-ban proxy that refuses every request with end code 0xC059
("command unsupported").

## Spec references
- Mitsubishi Electric SLMP Reference Manual SH(NA)-080956ENG —
  canonical protocol reference.
- MELSEC iQ-R / iQ-F / Q / L / FX Series CPU Module User's Manuals.
- ICS-CERT advisories on Mitsubishi MELSEC lacking authentication.

## Wire format (summary)
3E binary frame. 15-byte request, 29-byte success response
(or 13-byte error response). Frame layout in
`internal/protocols/slmp/wire/wire.go`:

Request:
```
50 00 00 FF FF 03 00 06 00 00 00 01 01 00 00
└─┬─┘ ▲   ▲   ▲   ▲   ▲     ▲     ▲     ▲
  │   │   │   │   │   │     │     │     subcommand 0x0000
  │   │   │   │   │   │     │     command 0x0101 (Read CPU model name)
  │   │   │   │   │   │     monitoring timer 0
  │   │   │   │   │   data length 6
  │   │   │   │   station 0
  │   │   │   IO 0x03FF (CPU)
  │   │   PC 0xFF
  │   network 0
  subheader 0x5000 (request)
```

Response (success):
```
D0 00 ROUTING(5) 14 00 00 00 [16-byte model] [2-byte CPU type LE]
└─┬─┘            ▲     ▲
  │              │     end code 0x0000
  │              data length 20 (= end code 2 + payload 18)
  subheader 0xD000 (response)
```

## Fingerprint strategy
One-shot probe over TCP. The Model string ("Q03UDVCPU",
"L26CPU-BT", "R04ENCPU", etc.) is the canonical signal — captured
into the finding hash so dedup is per-controller-model. Sentinel-
error classification surfaces in the note: short frame, length-
field mismatch, end-code refusal, wrong subheader, or generic
non-SLMP noise.

## Read operations (default build)
- `probe`: dials TCP/5007, sends BuildReadCPUModelName, reads the
  9-byte header, learns the declared length (capped at
  MaxResponseDataLength = 8192 to defuse oversized-length attacks),
  reads the body, parses with ParseReadCPUModelName.

## Write / dial operations (offensive build tag)
Deferred. SLMP supports Batch Write (0x1401), Random Write
(0x1402), Multiple Block Batch Write (0x1411), Remote RUN
(0x1620), Remote STOP (0x1621), Remote PAUSE (0x1622), Remote
LATCH CLEAR (0x1624), Remote RESET (0x1625), Clear Error (0x1619),
Password Lock/Unlock (0x1818/0x1819). Each needs per-(command,
subcommand) + per-device-range allowlist gating. Triple-confirm +
audit-chain emission per ADR-009.

## REPL commands (planned)
- See the generic REPL framework. Expose CPUInfo fields (Model,
  CPUType) read-only. A future REPL could decode the 2-byte type
  code against the Mitsubishi catalogue.

## Proxy hooks
Wire-layer write-ban: the default-build handler reads the first
frame's header, drains the body based on the declared length, and
replies with a 13-byte error frame carrying end code 0xC059 (the
SLMP "command unsupported" code). Does NOT forward — defence-in-
depth fail-closed pattern matching the Modbus / S7 / EtherNet/IP
proxy idioms.

## Scoring contribution
factors{protocol_risk:80, exposure:75, auth_state:95, capability:30
(75 on SLMP reply), impact_class:75, cve_exposure:0}. impact_class
75 reflects factory-floor PLC blast radius (RUN/STOP, force-set on
D / M / X / Y devices via Batch Write, error-log clearing).
auth_state 95 because SLMP has no native authentication — the
optional Password Lock/Unlock services (0x1818/0x1819) are
post-handshake and most deployments don't enable them.

## Sentinel errors (wire package)
- ErrShortFrame: < 11-byte response (header + end code).
- ErrNotResponse: subheader is not 0xD000 (either request frame
  loopback or non-SLMP).
- ErrLengthMismatch: declared length disagrees with buffer size,
  or declared length > MaxResponseDataLength.
- ErrEndCodeNonZero: CPU returned a non-zero end code (refusal /
  unsupported command).

These surface to the operator-facing note via `classifyParseError`
(plugin layer).
