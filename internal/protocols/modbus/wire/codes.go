package wire

// FunctionCode is the 7-bit Modbus function code (the high bit, when
// set in the response byte, signals an exception).
type FunctionCode uint8

// Canonical Modbus function codes covered by ElSereno. FC 8
// (Diagnostics) is a single code whose 16-bit sub-function straddles
// read/write; the offensive proxy gates it per sub-function via
// DiagIsReadOnly + a --diag-subfunction allowlist (see DiagSubFunction
// below), so it is classified CategoryDiagnostic rather than expanded
// here.
const (
	FCReadCoils                  FunctionCode = 0x01
	FCReadDiscreteInputs         FunctionCode = 0x02
	FCReadHoldingRegisters       FunctionCode = 0x03
	FCReadInputRegisters         FunctionCode = 0x04
	FCWriteSingleCoil            FunctionCode = 0x05
	FCWriteSingleRegister        FunctionCode = 0x06
	FCReadExceptionStatus        FunctionCode = 0x07
	FCDiagnostics                FunctionCode = 0x08
	FCGetCommEventCounter        FunctionCode = 0x0B
	FCGetCommEventLog            FunctionCode = 0x0C
	FCWriteMultipleCoils         FunctionCode = 0x0F
	FCWriteMultipleRegisters     FunctionCode = 0x10
	FCReportSlaveID              FunctionCode = 0x11
	FCReadFileRecord             FunctionCode = 0x14
	FCWriteFileRecord            FunctionCode = 0x15
	FCMaskWriteRegister          FunctionCode = 0x16
	FCReadWriteMultipleRegisters FunctionCode = 0x17
	FCReadFIFOQueue              FunctionCode = 0x18
	FCEncapsulatedInterface      FunctionCode = 0x2B // MEI, subcodes 13/14
)

// Category groups function codes for the proxy's allow/deny matrix.
type Category int

// Category values.
const (
	// CategoryUnknown is the fallback for FCs outside the spec table.
	CategoryUnknown Category = iota
	// CategoryRead covers functions that only read state.
	CategoryRead
	// CategoryWrite covers any function that can mutate device state.
	CategoryWrite
	// CategoryDiagnostic covers FC 8 (various sub-codes straddle
	// read/write; callers decide per sub-code).
	CategoryDiagnostic
	// CategoryMEI covers FC 43 (Encapsulated Interface Transport).
	// Sub-code 14 (Read Device Identification) is read-only; other
	// MEI sub-codes are forbidden by default.
	CategoryMEI
)

// Classify returns the Category for a function code.
func Classify(fc FunctionCode) Category {
	switch fc {
	case FCReadCoils, FCReadDiscreteInputs, FCReadHoldingRegisters,
		FCReadInputRegisters, FCReadExceptionStatus,
		FCGetCommEventCounter, FCGetCommEventLog,
		FCReportSlaveID, FCReadFileRecord,
		FCReadFIFOQueue:
		return CategoryRead
	case FCWriteSingleCoil, FCWriteSingleRegister,
		FCWriteMultipleCoils, FCWriteMultipleRegisters,
		FCWriteFileRecord, FCMaskWriteRegister,
		FCReadWriteMultipleRegisters:
		return CategoryWrite
	case FCDiagnostics:
		return CategoryDiagnostic
	case FCEncapsulatedInterface:
		return CategoryMEI
	default:
		return CategoryUnknown
	}
}

// DiagSubFunction is the 16-bit sub-function carried in the first data
// field of an FC 8 (Diagnostics) request, at PDU[1:3] big-endian. The
// Diagnostics family straddles read and write: some sub-functions only
// echo or return counters, others restart the device, silence it, or
// wipe forensic counters. The offensive proxy gates the mutating ones.
type DiagSubFunction uint16

// Diagnostics sub-functions (MODBUS Application Protocol Specification
// §6.8). The read/echo/counter set is benign; the rest change device
// state and must be explicitly allowlisted.
const (
	DiagReturnQueryData       DiagSubFunction = 0x0000 // loopback echo (read)
	DiagRestartComms          DiagSubFunction = 0x0001 // MUTATING: restart, can clear event log
	DiagReturnDiagRegister    DiagSubFunction = 0x0002 // read
	DiagChangeASCIIDelimiter  DiagSubFunction = 0x0003 // MUTATING: config change
	DiagForceListenOnly       DiagSubFunction = 0x0004 // MUTATING: DoS (slave stops answering)
	DiagClearCountersAndDiag  DiagSubFunction = 0x000A // MUTATING: wipes counters (anti-forensic)
	DiagReturnBusMsgCount     DiagSubFunction = 0x000B // read
	DiagReturnBusCommErrCount DiagSubFunction = 0x000C // read
	DiagReturnBusExcErrCount  DiagSubFunction = 0x000D // read
	DiagReturnSlaveMsgCount   DiagSubFunction = 0x000E // read
	DiagReturnSlaveNoRespCnt  DiagSubFunction = 0x000F // read
	DiagReturnSlaveNAKCount   DiagSubFunction = 0x0010 // read
	DiagReturnSlaveBusyCount  DiagSubFunction = 0x0011 // read
	DiagReturnBusOverrunCount DiagSubFunction = 0x0012 // read
	DiagClearOverrunCounter   DiagSubFunction = 0x0014 // MUTATING: clears overrun counter/flag
)

// DiagIsReadOnly reports whether a Diagnostics sub-function only echoes
// data or returns a counter (safe to forward without an allowlist).
// Everything outside this set: the known mutating sub-functions AND any
// reserved/vendor value, is treated as needing an explicit allowlist
// entry. Default-deny: an unrecognised sub-function is NOT read-only.
func DiagIsReadOnly(sub DiagSubFunction) bool {
	switch sub {
	case DiagReturnQueryData, DiagReturnDiagRegister,
		DiagReturnBusMsgCount, DiagReturnBusCommErrCount,
		DiagReturnBusExcErrCount, DiagReturnSlaveMsgCount,
		DiagReturnSlaveNoRespCnt, DiagReturnSlaveNAKCount,
		DiagReturnSlaveBusyCount, DiagReturnBusOverrunCount:
		return true
	default:
		return false
	}
}

// ExceptionCode is the one-byte code carried after a Modbus exception
// FC (FC | 0x80). See the MODBUS Application Protocol Specification
// §7 for the full table; the constants below cover every code
// ElSereno surfaces to findings.
type ExceptionCode uint8

// Exception codes.
const (
	ExIllegalFunction         ExceptionCode = 0x01
	ExIllegalDataAddress      ExceptionCode = 0x02
	ExIllegalDataValue        ExceptionCode = 0x03
	ExSlaveDeviceFailure      ExceptionCode = 0x04
	ExAcknowledge             ExceptionCode = 0x05
	ExSlaveDeviceBusy         ExceptionCode = 0x06
	ExMemoryParityError       ExceptionCode = 0x08
	ExGatewayPathUnavailable  ExceptionCode = 0x0A
	ExGatewayTargetNoResponse ExceptionCode = 0x0B
)

// IsException reports whether `rawFC` has the exception bit (0x80) set.
// Modbus encodes an exception response as `fc | 0x80` plus one byte of
// exception code.
func IsException(rawFC byte) bool { return rawFC&0x80 != 0 }
