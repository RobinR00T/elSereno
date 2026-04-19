package wire

// FunctionCode is the S7 parameter-area function byte. It lives in
// the first byte of the S7 parameter after the 10/12-byte S7 header
// (ROSCTR = Job / AckData / UserData).
type FunctionCode uint8

// S7 function codes covered by the proxy write-gating matrix
// (ADR-040). This list is not exhaustive; any function outside the
// table classifies as CategoryUnknown (default-deny posture).
const (
	FuncCommSetup       FunctionCode = 0xF0 // Setup Communication — read-category for the handshake
	FuncReadVar         FunctionCode = 0x04
	FuncWriteVar        FunctionCode = 0x05
	FuncRequestDownload FunctionCode = 0x1A
	FuncDownloadBlock   FunctionCode = 0x1B
	FuncDownloadEnded   FunctionCode = 0x1C
	FuncStartUpload     FunctionCode = 0x1D
	FuncUpload          FunctionCode = 0x1E
	FuncEndUpload       FunctionCode = 0x1F
	FuncPLCControl      FunctionCode = 0x28 // start / warm-restart / cold-restart — write-category
	FuncPLCStop         FunctionCode = 0x29
	FuncUserData        FunctionCode = 0x00 // ROSCTR 7 steers this branch
)

// Category groups S7 functions for the proxy allow/deny matrix.
type Category int

// Category values.
const (
	// CategoryUnknown is the fallback for functions outside the
	// classifier. Proxy refuses by default.
	CategoryUnknown Category = iota
	// CategoryRead covers the handshake and Read Var.
	CategoryRead
	// CategoryWrite covers any function that can mutate device
	// memory, block store, or run state (PLC Stop/Control).
	CategoryWrite
)

// Classify returns the Category for a function code. Callers extract
// the function byte with ExtractFunctionCode below; feeding 0x00 for
// a payload that does not include an S7 parameter returns
// CategoryUnknown.
func Classify(fc FunctionCode) Category {
	switch fc {
	case FuncCommSetup, FuncReadVar:
		return CategoryRead
	case FuncWriteVar,
		FuncRequestDownload, FuncDownloadBlock, FuncDownloadEnded,
		FuncStartUpload, FuncUpload, FuncEndUpload,
		FuncPLCControl, FuncPLCStop:
		return CategoryWrite
	default:
		return CategoryUnknown
	}
}

// ROSCTR values used for the S7 message-type byte.
const (
	ROSCTRJob      byte = 0x01
	ROSCTRAck      byte = 0x02
	ROSCTRAckData  byte = 0x03
	ROSCTRUserData byte = 0x07
)

// s7HeaderMin is the minimum bytes required before the parameter
// area: protoID(1) + ROSCTR(1) + redundancy(2) + pduRef(2) +
// paramLen(2) + dataLen(2) = 10. AckData adds 2 error bytes.
const s7HeaderMin = 10

// ExtractFunctionCode inspects a COTP Data payload carrying an S7
// PDU and returns (fc, true) when the parameter-area first byte is
// recoverable. It returns (0, false) for payloads that are too
// short, not S7 (protoID != 0x32), or for ROSCTR values that do not
// carry a parameter byte at the expected offset.
//
// payload here is the bytes AFTER the COTP header (i.e. what
// follows LI+type+TPDU-ref inside the TPKT envelope).
func ExtractFunctionCode(payload []byte) (FunctionCode, bool) {
	if len(payload) < s7HeaderMin {
		return 0, false
	}
	if payload[0] != 0x32 {
		return 0, false
	}
	rosctr := payload[1]
	off := s7HeaderMin
	if rosctr == ROSCTRAck || rosctr == ROSCTRAckData {
		off += 2
	}
	if off >= len(payload) {
		return 0, false
	}
	return FunctionCode(payload[off]), true
}

// BuildRefusalPayload returns the COTP+S7 payload (i.e. the bytes
// that follow the TPKT header) for a protocol-native refusal. The
// S7 PDU is an AckData with error class 0x85 (FuncCode not allowed)
// and error code 0x01. The reference echoes the request's PDU Ref
// so a real client correlates the refusal.
func BuildRefusalPayload(reqPayload []byte) []byte {
	pduRef := uint16(0)
	if len(reqPayload) >= s7HeaderMin {
		pduRef = uint16(reqPayload[4])<<8 | uint16(reqPayload[5])
	}
	// COTP DT: LI=02, type=0xF0, TPDU-nr=0x80 (end-of-TSDU marker).
	cotp := []byte{0x02, 0xF0, 0x80}
	// S7 AckData: protoID=0x32, ROSCTR=0x03, redundancy=0x0000,
	// pduRef(2), paramLen=0, dataLen=0, errClass=0x85, errCode=0x01.
	s7 := []byte{
		0x32, 0x03,
		0x00, 0x00,
		byte(pduRef >> 8), byte(pduRef & 0xFF),
		0x00, 0x00,
		0x00, 0x00,
		0x85, 0x01,
	}
	out := make([]byte, 0, len(cotp)+len(s7))
	out = append(out, cotp...)
	out = append(out, s7...)
	return out
}
