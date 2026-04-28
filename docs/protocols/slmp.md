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

Deferred. SLMP write services include:
- `0x1401` Batch Write (devices)
- `0x1402` Random Write
- `0x1411` Multiple Block Batch Write
- `0x1620` Remote RUN
- `0x1621` Remote STOP
- `0x1622` Remote PAUSE
- `0x1624` Remote LATCH CLEAR
- `0x1625` Remote RESET
- `0x1619` Clear Error
- `0x1818` Password Lock
- `0x1819` Password Unlock

A future offensive plugin would gate per-(command, subcommand)
plus per-device-range for Batch/Random writes (analogous to the
Modbus per-FC + per-address-range pattern in v1.12). Triple-confirm
+ audit-chain emission per ADR-009.

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
