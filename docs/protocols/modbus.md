# Modbus/TCP (port 502)

Modbus/TCP is the dominant industrial automation protocol. It has
**no authentication**: any client that can open a TCP connection to
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

FC 8 (Diagnostics) is gated per sub-function. The read/echo/counter
sub-functions (Return Query Data 0x00, Return Diagnostic Register
0x02, the counter reads 0x0B-0x12) forward freely. The mutating
sub-functions (Restart 0x01, Change ASCII Delimiter 0x03, Force
Listen Only 0x04, Clear Counters 0x0A, Clear Overrun 0x14) and any
reserved/vendor value are default-denied and answered with an
`IllegalFunction` exception. In the offensive build an operator can
open a specific mutating sub-function with `--diag-subfunction`
(see below); the default build denies them all.

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

### Gated proxy (v1.2+, structured YAML in v1.12+)

The library stores allowlist entries as `(unit, FC, start_addr,
end_addr)` tuples. v1.2 exposed only a function-code list;
v1.12 closes the round-trip gap so structured entries survive
`--emit-allow-file` lossless:

```sh
# Legacy: any unit, any address, just FC list.
elsereno-offensive write modbus proxy-dry-run \
  --target plc.internal:502 \
  --function 6 --function 16 \
  --vault-passphrase-file ~/.elsereno/dev.pp \
  --emit-allow-file /etc/elsereno/modbus-gate.yaml

# Structured (v1.12+): per-(unit, FC, start, end) tuples.
elsereno-offensive write modbus proxy-dry-run \
  --target plc.internal:502 \
  --write "unit=1;fc=6;start=100;end=200" \
  --write "unit=2;fc=16;start=400;end=500" \
  --vault-passphrase-file ~/.elsereno/dev.pp \
  --emit-allow-file /etc/elsereno/modbus-gate.yaml
```

YAML carries `functions:` (legacy) or `writes:` (structured):
the loader merges both. Refusal: Modbus IllegalFunction (0x01)
exception response.

### FC 8 Diagnostics sub-function gate

FC 8 carries a 16-bit sub-function at PDU[1:3]. Read/echo/counter
sub-functions forward without an allowlist. The mutating ones
(0x01 Restart, 0x03 Change ASCII Delimiter, 0x04 Force Listen Only,
0x0A Clear Counters, 0x14 Clear Overrun) and any reserved value are
default-denied. To authorise one, list it with `--diag-subfunction`
(repeatable, hex or decimal) on **both** the dry-run and the proxy;
the sub-function allowlist is bound into the confirm-token, so a
token minted for a narrow write allowlist cannot be reused to widen
the proxy with a diagnostic write:

```sh
# Authorise Force Listen Only (0x04) for a controlled resilience test.
elsereno-offensive write modbus proxy-dry-run \
  --target plc.internal:502 \
  --write "unit=1;fc=6;start=100;end=200" \
  --diag-subfunction 0x04 \
  --vault-passphrase-file ~/.elsereno/dev.pp \
  --emit-allow-file /etc/elsereno/modbus-gate.yaml
```

The emitted YAML round-trips the allowlist as `diag_subfunctions:`
(sorted `[]uint16`), so reloading the file reproduces the identical
token. Omitting `--diag-subfunction` (the default) denies every
mutating diagnostic. A minimal end-to-end demonstration, simulator
included, lives at `scripts/demo-modbus-proxy.sh`.

## Attack playbook (mapping to elSereno)

The techniques below follow the public Modbus attack literature
(Pascal Ackerman's "Modbus Attack & Defend" poster; the ICS-CERT
FrostyGoop / IRONGATE case write-ups). Each row states the on-wire
mechanism and exactly what elSereno does with it. elSereno is a
parsing write-gate and fingerprinter, not an IDS: its value is that
it forwards only what an operator has explicitly allowlisted, refuses
the rest at wire-parse time, and (with `--record`) captures every
frame that crossed the gate for post-incident review.

| Technique | Modbus mechanism | elSereno response |
|-----------|------------------|-------------------|
| Device / unit enumeration | FC 43/14 Read Device ID, FC 17 Report Slave ID, unit-id sweep | `probe` / `scan` surface the device banner (Vendor/Product/Revision); the proxy forwards these reads (they are read-only) and records them |
| Process-data harvesting | FC 1-4 bulk reads of coils / registers | Forwarded by design (the gate governs writes, not reads); with `--record` every read is timestamped for audit |
| Process manipulation (FrostyGoop pattern) | FC 3 read to map registers, then FC 16 / 6 write to change setpoints | Default build wire-bans all writes; offensive gate forwards a write only if it matches an allowlisted `(unit, FC, address-range)` tuple, otherwise IllegalFunction and upstream never sees it |
| Out-of-range write escalation | Allowlisted FC 16 write whose quantity runs off the top of the window | The gate checks **both** ends of the multi-register span, so a write that starts inside the window but overruns it is refused |
| Denial of service by silencing | FC 8/0x04 Force Listen Only: the slave stops answering the bus | Default-denied by the sub-function gate; IllegalFunction, never reaches the device. Authorise explicitly with `--diag-subfunction 0x04` only for a sanctioned resilience test |
| Device restart | FC 8/0x01 Restart Communications (data 0xFF00 also clears the event log) | Default-denied; requires `--diag-subfunction 0x01` |
| Anti-forensics | FC 8/0x0A Clear Counters, FC 8/0x14 Clear Overrun: wipe the diagnostic counters an investigator would read | Default-denied; requires an explicit `--diag-subfunction` entry, and the attempt itself is recorded |
| Config tamper | FC 8/0x03 Change ASCII Input Delimiter | Default-denied; requires `--diag-subfunction 0x03` |
| Reserved / vendor diagnostics abuse | FC 8 with an undocumented sub-function | Default-denied (the read-only set is an allowlist, not a blocklist), so unknown sub-functions fail closed |
| Malformed-frame / parser abuse | Truncated MBAP, short PDU, FC 8 with no sub-function | The wire parser bounds-checks; a malformed FC 8 fails closed (refused, not forwarded) |

Note the deliberate asymmetry: reads forward (a passive tap should
not break the process it observes), writes and mutating diagnostics
are default-denied. An operator running a sanctioned test opens the
exact write or sub-function needed and nothing else, and the record
file is the evidence trail.

## Scope

- PLC memory region; read yields process-critical values (tank
  levels, valve states, setpoints).
- Write impact: direct physical effect (pumps, valves, motors).
  Safety-critical.

## Public references

- MODBUS Messaging on TCP/IP V1.0b.
- MODBUS Application Protocol Specification V1.1b3.
- MODBUS-IDA §6.21 (Read Device Identification).
