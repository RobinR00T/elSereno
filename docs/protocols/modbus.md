# Modbus/TCP (port 502)

Modbus/TCP is the dominant industrial automation protocol. It has
**no authentication** — any client that can open a TCP connection to
port 502 can read and write coil, discrete-input, holding-register,
and input-register tables.

## Probe

- FC 1 (Read Coils) against address 0, quantity 1. The smallest
  legal Modbus read; any live PLC responds without side effects.
- FC 43 / sub-code 14 (Read Device Identification) opportunistically
  to capture Vendor / Product / Revision strings.

## Proxy policy (default build)

Wire-layer write-ban. Every frame is parsed; the function code is
classified, and any **CategoryWrite** FC (5 / 6 / 15 / 16 / 22 / 23,
write-file-record, mask-write-register) short-circuits to an
`IllegalFunction` exception response. Upstream never receives the
write frame.

FC 43 only forwards sub-code 14 (Read Device Identification).
Other MEI sub-codes are blocked.

FC 8 (Diagnostics) is currently treated as CategoryUnknown and
blocked; per-sub-code handling lands in F6.

## Writes (`-tags offensive`)

`offensive/write/modbus` implements FC 5 / 6 / 15 / 16 with
deterministic SHA-256 payload hashes so the triple-confirm token is
stable across dry-run and real-run.

| Op                           | FC |
|------------------------------|----|
| `write_single_coil`          | 5  |
| `write_single_register`      | 6  |
| `write_multiple_coils`       | 15 |
| `write_multiple_registers`   | 16 |

## Scope

- PLC memory region; read yields process-critical values (tank
  levels, valve states, setpoints).
- Write impact: direct physical effect (pumps, valves, motors).
  Safety-critical.

## Public references

- MODBUS Messaging on TCP/IP V1.0b.
- MODBUS Application Protocol Specification V1.1b3.
- MODBUS-IDA §6.21 (Read Device Identification).
