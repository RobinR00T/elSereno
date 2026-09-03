---
phase: F3
status: implemented
last-updated: 2026-09-03
token-budget: 1500
protocol-name: modbus
default-port: 502/tcp
---

# Modbus/TCP

## TL;DR
Modbus/TCP has no authentication. ElSereno's default build probes
with FC 1 (Read Coils, 1 coil, address 0) and opportunistically
reads FC 43/14 device-id strings. The proxy blocks every
CategoryWrite function code at the wire layer and replies to the
client with IllegalFunction so a deployed proxy cannot mutate a
PLC, regardless of the upstream configuration.

## Spec references
- MODBUS Messaging on TCP/IP V1.0b.
- MODBUS Application Protocol Specification V1.1b3.
- FC 43 / 14: MODBUS-IDA §6.21 Read Device Identification.

## Wire format (summary)
- MBAP (7 bytes): TxID (uint16 BE), ProtocolID (uint16 BE, 0),
  Length (uint16 BE, covers Unit+PDU), Unit (uint8).
- PDU: [FC][data…], max 253 bytes.
- Exception: FC with high bit set (0x80), plus one byte of exception
  code.

## Fingerprint strategy
- `probe`: send FC 1 (Read Coils, address=0, count=1); classify the
  response.
  - FC 1 with 1-byte data -> "read-coils accepted"
  - FC 0x81 + exception code -> "exception on FC1: 0x__"
- `device-id`: opportunistic FC 43/14 level 0x01 (Basic). When
  supported, the response carries VendorName (obj 0x00),
  ProductCode (obj 0x01), MajorMinorRevision (obj 0x02). These
  strings feed the finding's vendor/product/revision annotation.

## Read operations (default build)
- `probe`: what scan invokes.
- Planned F4 REPL commands: `read_coils`, `read_discrete`,
  `read_holding`, `read_input`, `device_id`.

## Write / dial operations (offensive build tag)
Deferred to F5. The offensive build adds write commands with triple
confirm: `write_single_coil`, `write_single_register`,
`write_multiple_coils`, `write_multiple_registers`,
`mask_write_register`, `read_write_multiple_registers`, and the
file-record writer.

## REPL commands (planned F4)
See above.

## Proxy hooks
The proxy handler enforces the read-only policy by parsing each
client frame and short-circuiting writes with IllegalFunction:

| FC | Name | Category | Action |
|----|------|----------|--------|
| 0x01-0x04 | Read Coils / Discrete / Holding / Input | Read | forward |
| 0x05 | Write Single Coil | Write | block |
| 0x06 | Write Single Register | Write | block |
| 0x07 | Read Exception Status | Read | forward |
| 0x08 | Diagnostics | Diagnostic | per-sub-function (read forward; mutating default-deny) |
| 0x0B | Get Comm Event Counter | Read | forward |
| 0x0C | Get Comm Event Log | Read | forward |
| 0x0F | Write Multiple Coils | Write | block |
| 0x10 | Write Multiple Registers | Write | block |
| 0x11 | Report Slave ID | Read | forward |
| 0x14 | Read File Record | Read | forward |
| 0x15 | Write File Record | Write | block |
| 0x16 | Mask Write Register | Write | block |
| 0x17 | Read/Write Multiple Registers | Write | block |
| 0x18 | Read FIFO Queue | Read | forward |
| 0x2B | Encapsulated Interface | MEI | forward sub-code 0x0E only |

### FC 8 Diagnostics sub-function gate (offensive proxy)
FC 8 carries a 16-bit sub-function at PDU[1:3]. `mbwire.DiagIsReadOnly`
defines the read/echo/counter allowlist (0x00 Return Query Data, 0x02
Return Diagnostic Register, 0x0B-0x12 counters); those forward. Every
other sub-function, the mutating ones (0x01 Restart, 0x03 Change ASCII
Delimiter, 0x04 Force Listen Only, 0x0A Clear Counters, 0x14 Clear
Overrun) and any reserved/vendor value, is default-denied and answered
with IllegalFunction. The offensive gate opens a specific mutating
sub-function via `WriteGatedHandler.AllowedDiag` (`--diag-subfunction`
on the CLI, `diag_subfunctions:` in the allow-file). The allowlist is
bound into the confirm-token through `AllowlistHashWithDiag`, which
degrades byte-for-byte to `AllowlistHashWithGeneration` when the diag
list is empty, so every pre-existing token stays valid. A truncated
FC 8 (no sub-function) fails closed.

## Known quirks / vendor deltas
- Some HMI software issues FC 23 (Read/Write Multiple Registers)
  even for read-only dashboards. The proxy blocks it because the
  write component cannot be severed; operators that need it bypass
  the proxy themselves.
- A handful of legacy devices answer FC 43/14 with ExIllegalFunction:
  unsupported is correct, not a bug.

## Test vectors
- `simulators/modbus/` responds to FC 1/2/3/4 against an in-memory
  bank, echoes FC 8/0x00 (Return Query Data) and returns zero counters
  for the FC 8 reads, and refuses writes plus every mutating FC 8
  sub-function with IllegalFunction.
- `internal/protocols/modbus/wire/diag_test.go` covers the diag
  classifier + extractor; `offensive/write/modbus/diag_test.go` covers
  the gate decisions + the token-hash backwards-compat ladder.
- Fuzz targets: `FuzzParseMBAP`, `FuzzReadFrameRoundTrip`,
  `FuzzDeviceIDObjects`.
- Integration test `test/integration/modbus_integration_test.go`
  drives the proxy framework end-to-end with a Write Single Coil
  and asserts IllegalFunction is returned without touching upstream.

## Scoring contribution
- `protocol_risk=85` (unauthenticated OT path).
- `exposure=80` baseline; drops only if scope.yaml narrows it.
- `auth_state=90` (no native auth).
- `capability=60` when read-confirmed devices surface state.
- `impact_class=70` (writable controllers affect physical process).

## Open questions
- Whether to expose `--protocols=modbus` autotargeting alongside the
  atmodem CandidatePorts pattern so `scan --input list:*` can
  auto-select Modbus targets. Target for F4.
