package wire

import (
	"encoding/binary"
	"math"
)

// Analog Output Block (Group 41) decoding. IEEE 1815 §A.13; field
// order (value then a 1-octet control status) matches the Wireshark
// DNP3 dissector packet-dnp3.c. An Operate / Direct Operate carrying a
// g41 object writes an analog setpoint (a valve position, a voltage or
// speed reference, ...), so it moves the physical process just like a
// CROB and the gate scopes it the same way.

// GroupAnalogOutput is the DNP3 object group for Analog Output Blocks.
const GroupAnalogOutput uint8 = 41

// Analog Output Block variations. Each object is the value followed by
// a 1-octet control status.
const (
	VarAnalogOutInt32   uint8 = 1 // 4-octet signed integer
	VarAnalogOutInt16   uint8 = 2 // 2-octet signed integer
	VarAnalogOutFloat32 uint8 = 3 // 4-octet IEEE 754 single
	VarAnalogOutFloat64 uint8 = 4 // 8-octet IEEE 754 double
)

// AnalogPoint is one (index, setpoint) pair from a g41 Analog Output
// Block. Value is widened to float64 regardless of the on-wire
// variation so the gate can range-check every variation uniformly.
type AnalogPoint struct {
	Index uint16
	Value float64
}

// analogValueSize returns the on-wire value size in octets (excluding
// the status octet) for a g41 variation, or (0,false) if unsupported.
func analogValueSize(variation uint8) (int, bool) {
	switch variation {
	case VarAnalogOutInt32, VarAnalogOutFloat32:
		return 4, true
	case VarAnalogOutInt16:
		return 2, true
	case VarAnalogOutFloat64:
		return 8, true
	default:
		return 0, false
	}
}

// decodeAnalogValue reads the little-endian value at b[:size] for the
// given variation and widens it to float64.
func decodeAnalogValue(b []byte, variation uint8) float64 {
	switch variation {
	case VarAnalogOutInt32:
		// #nosec G115 -- two's-complement reinterpretation of a fixed 4-octet field
		return float64(int32(binary.LittleEndian.Uint32(b)))
	case VarAnalogOutInt16:
		// #nosec G115 -- two's-complement reinterpretation of a fixed 2-octet field
		return float64(int16(binary.LittleEndian.Uint16(b)))
	case VarAnalogOutFloat32:
		return float64(math.Float32frombits(binary.LittleEndian.Uint32(b)))
	case VarAnalogOutFloat64:
		return math.Float64frombits(binary.LittleEndian.Uint64(b))
	default:
		return 0
	}
}

// ExtractAnalogOutputs parses the first APDU object header and, when it
// is a g41 Analog Output Block (variations 1-4), returns each (index,
// value) pair. Semantics mirror ExtractCROBs: (nil,true) when the first
// object is not a g41, (nil,false) on truncation or an unsupported
// variation/qualifier (fail-closed). `apdu` starts at the first object
// header (group octet).
func ExtractAnalogOutputs(apdu []byte) (points []AnalogPoint, ok bool) {
	if len(apdu) < 3 {
		return nil, true
	}
	if apdu[0] != GroupAnalogOutput {
		return nil, true // not an analog output
	}
	variation := apdu[1]
	valSize, sizeOK := analogValueSize(variation)
	if !sizeOK {
		return nil, false // unsupported g41 variation
	}
	objLen := valSize + 1 // value + 1-octet control status
	switch apdu[2] {
	case 0x17: // 1-octet index prefix, 1-octet count
		return analogIndexPrefix(apdu, 3, 1, 1, objLen, valSize, variation)
	case 0x28: // 2-octet index prefix, 2-octet count
		return analogIndexPrefix(apdu, 3, 2, 2, objLen, valSize, variation)
	case 0x00: // 1-octet start-stop range
		return analogStartStop(apdu, 3, 1, objLen, valSize, variation)
	case 0x01: // 2-octet start-stop range
		return analogStartStop(apdu, 3, 2, objLen, valSize, variation)
	default:
		return nil, false
	}
}

func analogIndexPrefix(apdu []byte, pos, countSize, idxSize, objLen, valSize int, variation uint8) ([]AnalogPoint, bool) {
	count, pos, ok := readUint(apdu, pos, countSize)
	if !ok {
		return nil, false
	}
	points := make([]AnalogPoint, 0, int(count))
	for i := 0; i < int(count); i++ {
		idx, next, okIdx := readUint(apdu, pos, idxSize)
		if !okIdx || next+objLen > len(apdu) {
			return nil, false
		}
		points = append(points, AnalogPoint{Index: idx, Value: decodeAnalogValue(apdu[next:next+valSize], variation)})
		pos = next + objLen
	}
	return points, true
}

func analogStartStop(apdu []byte, pos, size, objLen, valSize int, variation uint8) ([]AnalogPoint, bool) {
	start, pos, ok := readUint(apdu, pos, size)
	if !ok {
		return nil, false
	}
	stop, pos, ok := readUint(apdu, pos, size)
	if !ok || stop < start {
		return nil, false
	}
	points := make([]AnalogPoint, 0, int(stop-start)+1)
	for idx := start; idx <= stop; idx++ {
		if pos+objLen > len(apdu) {
			return nil, false
		}
		points = append(points, AnalogPoint{Index: idx, Value: decodeAnalogValue(apdu[pos:pos+valSize], variation)})
		pos += objLen
	}
	return points, true
}
