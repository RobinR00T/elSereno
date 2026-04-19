package wire

// FunctionCode is the 7-bit Modbus function code (the high bit, when
// set in the response byte, signals an exception).
type FunctionCode uint8

// Canonical Modbus function codes covered by ElSereno. Omitted from
// this list are the Diagnostics family (FC 8 sub-codes) because they
// straddle read/write; the proxy treats them as Category(Unknown)
// until F5 adds per-sub-code gating.
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
