# MELSEC SLMP (port 5007)

SLMP (SeamLess Message Protocol) is the modern (2014+) Mitsubishi
Electric replacement for MELSEC-A/3C/MC. It ships across the
iQ-R, iQ-F, Q-, L-, and FX-series PLCs and many compatible HMIs
and motion controllers. TCP/5007 is the default; UDP/5007 also
exists but TCP is by far the most common Internet-exposed shape.

## Probe

- Send the 15-byte READ CPU MODEL NAME 3E-frame request (command
  0x0101, subcommand 0x0000, no monitoring timer).
- Expect a 29-byte success response: subheader 0xD000 + 7 routing
  bytes + ResponseDataLength 0x0014 + end code 0x0000 + 16-byte
  ASCII Model + 2-byte little-endian CPU type code.
- The Model field ("Q03UDVCPU", "L26CPU-BT", "R04ENCPU", etc.) is
  folded into the finding hash so dedup is per-controller-model.
  The CPU type code is exposed in the operator-facing note as
  `type=0x4612` for cross-referencing against the Mitsubishi
  catalogue.

The probe is idempotent and side-effect-free: READ CPU MODEL NAME
does not touch memory devices, latches, or program memory — it
returns the CPU's self-description.

## Wire layout (3E binary frame)

```
Request (15 bytes):
  Offset  Field                       Size  Value
  0..1    Subheader                   2     0x5000 LE  (= request)
  2       Network No                  1     0x00       (host)
  3       PC No                       1     0xFF       (CPU)
  4..5    Dest Module IO              2     0x03FF LE  (CPU)
  6       Dest Module Station         1     0x00
  7..8    Request Data Length         2     0x0006 LE
  9..10   Monitoring Timer            2     0x0000     (no timeout)
  11..12  Command                     2     0x0101 LE  (Read CPU model name)
  13..14  Subcommand                  2     0x0000

Response (29 bytes, success):
  0..1    Subheader                   2     0xD000 LE  (= response)
  2..6    routing fields (echo)       5
  7..8    Response Data Length        2     0x0014 LE
  9..10   End Code                    2     0x0000     (success)
  11..26  CPU Model Name              16    ASCII, padded with 0x20
  27..28  CPU Type Code               2     LE
```

## Proxy policy (default build)

SLMP is **TCP**, so the generic proxy framework applies. The
default-build handler reads the first frame's request data length,
drains the body, and replies with a 13-byte error frame carrying
end code 0xC059 ("command unsupported" per SLMP §6.6 end-code
table). It does NOT forward to upstream — defence-in-depth: a
malformed length could bypass a request classifier, so we
fail-closed for every request in the default build.

Refusal idiom: subheader 0xD000 + routing echo + declared length
0x0002 + end code 0xC059.

## Writes (`-tags offensive`)

Shipped. The write-gated TCP proxy lives in `offensive/write/slmp`
(ADR-040 template, mirrors the s7 length-prefixed handler).
Per-frame classification via `wire.ReadFrame` (one 3E-binary frame
at a time): reads (Device Read, Read CPU Model Name, ...) always
pass; a mutating command is admitted only when its command code is
allowlisted.

```sh
# 1) Mint the session confirm-token (ADR-039 triple-confirm):
elsereno-offensive write slmp proxy-dry-run \
  --target plc.internal:5007 \
  --slmp-command 0x1401 \          # Device Write Batch
  --slmp-command 0x1002 \          # Remote Stop
  --slmp-device 0xA8 \             # optional: narrow the batch write to D (0xA8), M (0x90), ...
  --vault-passphrase-file ~/.elsereno/dev.pp

# 2) Run the gated proxy (TCP/5007) with the triple-confirm fence:
elsereno-offensive proxy listen --plugin slmp \
  --listen 127.0.0.1:5007 --target plc.internal:5007 \
  --slmp-command 0x1401 --slmp-command 0x1002 --slmp-device 0xA8 \
  --accept-writes --confirm-target plc.internal:5007 \
  --confirm-token <token-from-dry-run> \
  --vault-passphrase-file ~/.elsereno/dev.pp
```

Flags: `--slmp-command <u16>` (command code, decimal or `0x..`,
repeatable; e.g. `0x1401` Device Write Batch, `0x1002` Remote Stop)
and `--slmp-device <byte>` (optionally narrows an allowed Device
Write Batch, subcommand `0x0000`, to specific device codes; empty =
any device).

**Refusal semantics**: a refused frame gets a **native SLMP
response** (end code `0xC059`, "command cannot be executed") written
back to the client and never forwarded upstream (ADR-040); the two
client-writing goroutines share a locked writer so refusal and
response frames never interleave. The wire parser + device codes
come from `internal/protocols/slmp/wire` (Mitsubishi SLMP Reference
SH(NA)-080956ENG). Triple-confirm + audit-chain emission per
ADR-039.

Out of scope for this cycle: per-device-address narrowing within an
allowed Device Write (the SLMP analogue of the s7 per-item gate).

## Scope

- Mitsubishi Electric CPUs in automotive (the canonical
  Mitsubishi PLC market), packaging, food & beverage,
  semiconductor fabs.
- Compatible Mitsubishi GOT HMIs and MR-J3/J4/J5 servo amps.
- Impact: a writeable SLMP endpoint can stop a CPU
  (RUN→STOP→RESET cascade), force device values (forced-set on D
  / M / X / Y devices via Batch Write), or clear error logs that
  would otherwise alert maintenance.

## Public references

- Mitsubishi Electric SLMP Reference Manual SH(NA)-080956ENG
  (canonical protocol reference; download from MELFANS portal).
- MELSEC iQ-R / iQ-F / Q / L Series CPU Module User's Manual.
- ICS-CERT advisories on Mitsubishi MELSEC lacking authentication
  on the default port (multiple, 2018-onwards).
- Talos blog "MELSEC over Internet" (Cisco Talos, 2020) — surveys
  Internet-exposed CPUs.
