# GE-SRTP (port 18245)

GE-SRTP (GE Service Request Transfer Protocol) is the proprietary
protocol for GE Fanuc / Emerson PACSystems / Series 90-30 / Series
90-70 / Series 90-Micro / RX3i / RX7i PLCs and many compatible
HMIs and SCADA gateways. TCP/18245 is the default; some
PACSystems also bind 18246 for a backup/extended frame.

## Probe

- Send the canonical 56-byte CONNECTION INIT mailbox: byte 0 =
  0x02, every other byte zero. SRTP is mailbox-framed (every
  request and response is exactly 56 bytes for the basic
  service-request set).
- Expect a 56-byte response with byte 0 = 0x03 (response
  indicator).
- **v1.21 chunk 4 refinement**: scan the response payload (bytes
  1..55) for printable-ASCII runs matching the canonical GE PLC
  family prefixes (PACSystems / IC693 / IC695 / IC697 / IC200 /
  RX3i / RX7i). When a model hint is extracted (e.g.,
  "IC695CPE330"), it folds into the finding hash and lifts the
  capability factor from 70 to 75 — same delta finsudp / slmp
  get for parsed model strings.

Service 0x21 (Read PLC Long Status) probing — a richer follow-up
that explicitly asks the CPU for its model + firmware version —
is left for a future cycle that can carry test vectors against
real PLCs.

The probe is idempotent and side-effect-free: CONNECTION INIT is
the SRTP equivalent of a TCP handshake — no memory areas, no
program blocks, no service-request payloads.

## Wire layout (mailbox)

```
Offset  Field                  Size  Description
0       Type                   1     0x02 = request, 0x03 = response
1..7    Reserved / unused      7     Zero on init
8..9    Packet number          2     Set on follow-up service requests
10..11  Sequence number        2     Set on follow-up service requests
12..29  Various                18    Service-specific
30..31  Service request code   2     Set on follow-up service requests
                                     (0x21 = read CPU long status)
32..49  Service-specific       18    Empty on init
50..55  End of mailbox         6     Zero on init
```

The 56-byte zero-with-0x02-prefix on initialisation means the
response carries the PLC's connection-acceptance flags and an
internally-allocated mailbox ID that subsequent service-request
mailboxes echo. The plugin doesn't parse those fields for v1.20
chunk 3 — the response shape alone is enough for fingerprinting.

## Proxy policy (default build)

SRTP is **TCP**. The default-build handler reads the first 56-byte
mailbox from the client and replies with a 56-byte mailbox
carrying byte 0 = 0x03 (response) + byte 42 = 0x01 (a non-zero
"status / minor error" indicator in the public reverse-engineering
notes — compatible clients treat this as "request not honoured"
and back off rather than retry). It does NOT forward to upstream
— defence-in-depth fail-closed pattern matching the Modbus / S7 /
EtherNet/IP proxy idioms.

## Writes (`-tags offensive`)

Deferred. SRTP supports the following write-class service request
codes (from public reverse engineering):
- `0x07` Write system memory
- `0x09` Write PLC memory
- `0x0F` Write program block
- `0x10` Write memory by symbolic name
- `0x18` RUN command
- `0x19` STOP command
- `0x1A` Reset command

A future offensive plugin would gate per-service-code +
per-memory-area allowlist (analogous to the Modbus per-FC +
per-address-range pattern in v1.12). Triple-confirm + audit-chain
emission per ADR-009.

## Scope

- GE Fanuc / Emerson PACSystems CPUs (RX3i, RX7i, Series 90-30,
  Series 90-70, Series 90-Micro) in oil & gas, water treatment,
  power generation, paper mills.
- Compatible GE QuickPanel and Cimplicity HMIs.
- Impact: a writeable SRTP endpoint can stop a CPU (RUN→STOP),
  rewrite memory areas (D / I / Q / M / G / R), or transfer
  program blocks (full ladder logic replacement). Stopping a
  PACSystems CPU on a SCADA fleet trips downstream alarms across
  the operator's HMI dashboard.

## Public references

- Rapid7 nmap NSE script `gesrtp-info` — the canonical public
  reverse-engineering effort.
- Conpot project — GE simulator fixtures that document the
  on-wire shape used by this plugin.
- ICS-CERT advisories on GE Fanuc PACSystems lacking
  authentication on the default port (multiple, 2014-onwards).
