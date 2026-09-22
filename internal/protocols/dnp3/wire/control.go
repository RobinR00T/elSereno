package wire

// Application-layer control decoding: broadcast addressing, the
// Control Relay Output Block (Group 12 Variation 1) and its control
// code. IEEE 1815 Table 4-1 (function codes), §A.11 (g12v1).

// IsBroadcast reports whether dest is a DNP3 broadcast link address
// (0xFFFD all-stations-no-confirm, 0xFFFE all-stations-confirm,
// 0xFFFF). A control or write to a broadcast address reaches every
// outstation on the loop at once and cannot be scoped to one device.
func IsBroadcast(dest uint16) bool { return dest >= 0xFFFD }

// Application-layer function codes (IEEE 1815 Table 4-1). Only the
// subset the gate reasons about is named here.
const (
	AppReadCode            uint8 = 0x01
	AppWriteCode           uint8 = 0x02
	AppSelectCode          uint8 = 0x03
	AppOperateCode         uint8 = 0x04
	AppDirectOperateCode   uint8 = 0x05
	AppDirectOperateNRCode uint8 = 0x06
	AppFreezeClearCode     uint8 = 0x09
	AppDisableUnsolicited  uint8 = 0x15 // silences the outstation (denial of view)
	AppColdRestartCode     uint8 = 0x0D
	AppWarmRestartCode     uint8 = 0x0E
	AppInitializeDataCode  uint8 = 0x0F
	AppStopApplicationCode uint8 = 0x12
	AppSaveConfigCode      uint8 = 0x13
	AppActivateConfigCode  uint8 = 0x1F
)

// AppIsControl reports whether an application-layer function code
// issues a control that may carry a Control Relay Output Block
// (Select, Operate, Direct Operate, Direct Operate No-Ack).
func AppIsControl(fc uint8) bool {
	switch fc {
	case AppSelectCode, AppOperateCode, AppDirectOperateCode, AppDirectOperateNRCode:
		return true
	default:
		return false
	}
}

// Group/variation of the Control Relay Output Block.
const (
	GroupBinaryOutputControl uint8 = 12
	VarCROB                  uint8 = 1
)

// CROB control-code fields (IEEE 1815 §A.11). The byte is laid out as
// [TCC:2][C:1][Q:1][OpType:4].
const (
	TCCNul   uint8 = 0
	TCCClose uint8 = 1
	TCCTrip  uint8 = 2

	OpNul      uint8 = 0
	OpPulseOn  uint8 = 1
	OpPulseOff uint8 = 2
	OpLatchOn  uint8 = 3
	OpLatchOff uint8 = 4
)

// CROBTCC extracts the Trip/Close field (bits 7-6).
func CROBTCC(code uint8) uint8 { return (code >> 6) & 0x03 }

// CROBOpType extracts the operation type (bits 3-0).
func CROBOpType(code uint8) uint8 { return code & 0x0F }

// CROBIsTripClose reports whether the control code trips or closes a
// breaker (TCC != NUL). This is the destructive intent the DNP3
// attack literature flags: 0x81 = TRIP+PULSE_ON, 0x41 = CLOSE+PULSE_ON.
func CROBIsTripClose(code uint8) bool { return CROBTCC(code) != TCCNul }

// crobLen is the fixed size of one g12v1 object: control code(1) +
// count(1) + on-time(4) + off-time(4) + status(1).
const crobLen = 11

// ControlPoint is one (index, control-code) pair extracted from a
// g12v1 Control Relay Output Block in a control request.
type ControlPoint struct {
	Index       uint16
	ControlCode uint8
}

// ExtractCROBs parses the first application-layer object header of an
// APDU object region and, when it is a g12v1 Control Relay Output
// Block, returns each (index, control-code) pair. `apdu` must start at
// the first object header (group octet), i.e. after the transport
// header + application control + function code.
//
// Returns ok=false when the first object is a g12v1 but its encoding
// is truncated or uses a qualifier this parser does not support: the
// gate treats that as a refusal (fail-closed). When the first object
// is not a g12v1, it returns (nil, true): there is no CROB to scope.
//
// Supported qualifiers: 0x17 / 0x28 (index-prefix + count) and
// 0x00 / 0x01 (start-stop range). These are what a real Operate /
// Direct Operate against breakers uses.
func ExtractCROBs(apdu []byte) (points []ControlPoint, ok bool) {
	if len(apdu) < 3 {
		return nil, true // no room for an object header: nothing to scope
	}
	if apdu[0] != GroupBinaryOutputControl || apdu[1] != VarCROB {
		return nil, true // not a CROB
	}
	qualifier := apdu[2]
	switch qualifier {
	case 0x17: // 1-octet index prefix, 1-octet count
		return crobsIndexPrefix(apdu, 3, 1, 1)
	case 0x28: // 2-octet index prefix, 2-octet count
		return crobsIndexPrefix(apdu, 3, 2, 2)
	case 0x00: // 1-octet start-stop range
		return crobsStartStop(apdu, 3, 1)
	case 0x01: // 2-octet start-stop range
		return crobsStartStop(apdu, 3, 2)
	default:
		return nil, false // g12v1 with an unsupported qualifier: fail closed
	}
}

// crobsIndexPrefix parses the index-prefix qualifiers (0x17 / 0x28).
// countSize and idxSize are 1 or 2 octets.
func crobsIndexPrefix(apdu []byte, pos, countSize, idxSize int) ([]ControlPoint, bool) {
	count, pos, ok := readUint(apdu, pos, countSize)
	if !ok {
		return nil, false
	}
	points := make([]ControlPoint, 0, int(count))
	for i := 0; i < int(count); i++ {
		idx, next, okIdx := readUint(apdu, pos, idxSize)
		if !okIdx || next+crobLen > len(apdu) {
			return nil, false
		}
		points = append(points, ControlPoint{Index: idx, ControlCode: apdu[next]})
		pos = next + crobLen
	}
	return points, true
}

// crobsStartStop parses the start-stop qualifiers (0x00 / 0x01). Each
// index in [start, stop] carries one CROB in order, with no per-point
// index prefix.
func crobsStartStop(apdu []byte, pos, size int) ([]ControlPoint, bool) {
	start, pos, ok := readUint(apdu, pos, size)
	if !ok {
		return nil, false
	}
	stop, pos, ok := readUint(apdu, pos, size)
	if !ok || stop < start {
		return nil, false
	}
	points := make([]ControlPoint, 0, int(stop-start)+1)
	for idx := start; idx <= stop; idx++ {
		if pos+crobLen > len(apdu) {
			return nil, false
		}
		points = append(points, ControlPoint{Index: idx, ControlCode: apdu[pos]})
		pos += crobLen
	}
	return points, true
}

// readUint reads a 1- or 2-octet little-endian unsigned value at
// apdu[pos] and returns it (as a uint16, since a DNP3 count or index is
// at most two octets) with the advanced position.
func readUint(apdu []byte, pos, size int) (val uint16, next int, ok bool) {
	if pos+size > len(apdu) {
		return 0, pos, false
	}
	switch size {
	case 1:
		return uint16(apdu[pos]), pos + 1, true
	case 2:
		return uint16(apdu[pos]) | uint16(apdu[pos+1])<<8, pos + 2, true
	default:
		return 0, pos, false
	}
}
