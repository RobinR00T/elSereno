package wire

import (
	"encoding/binary"
	"math"
	"testing"
)

// aobInt32 builds a g41v1 single-point Analog Output Block (qualifier
// 0x17) at index with the given int32 setpoint.
func aobInt32(index uint8, v int32) []byte {
	out := []byte{GroupAnalogOutput, VarAnalogOutInt32, 0x17, 0x01, index}
	var val [4]byte
	// #nosec G115 -- int32->uint32 bit reinterpretation for LE encoding (test)
	binary.LittleEndian.PutUint32(val[:], uint32(v))
	out = append(out, val[:]...)
	return append(out, 0x00) // control status
}

func TestExtractAnalogOutputs_Int32(t *testing.T) {
	t.Parallel()
	points, ok := ExtractAnalogOutputs(aobInt32(9, -4200))
	if !ok || len(points) != 1 {
		t.Fatalf("ok=%v points=%d, want true 1", ok, len(points))
	}
	if points[0].Index != 9 || points[0].Value != -4200 {
		t.Fatalf("point = %+v, want {9, -4200}", points[0])
	}
}

func TestExtractAnalogOutputs_Float32(t *testing.T) {
	t.Parallel()
	apdu := []byte{GroupAnalogOutput, VarAnalogOutFloat32, 0x17, 0x01, 0x03}
	var val [4]byte
	binary.LittleEndian.PutUint32(val[:], math.Float32bits(72.5))
	apdu = append(apdu, val[:]...)
	apdu = append(apdu, 0x00)
	points, ok := ExtractAnalogOutputs(apdu)
	if !ok || len(points) != 1 || points[0].Index != 3 || points[0].Value != 72.5 {
		t.Fatalf("ExtractAnalogOutputs = %v %+v, want ok=true {3, 72.5}", ok, points)
	}
}

func TestExtractAnalogOutputs_TwoOctetIndex(t *testing.T) {
	t.Parallel()
	// qualifier 0x28: 2-octet count + 2-octet index prefix, g41v2 (int16).
	apdu := []byte{GroupAnalogOutput, VarAnalogOutInt16, 0x28, 0x01, 0x00, 0x02, 0x01}
	var val [2]byte
	binary.LittleEndian.PutUint16(val[:], uint16(int16(1000)))
	apdu = append(apdu, val[:]...)
	apdu = append(apdu, 0x00)
	points, ok := ExtractAnalogOutputs(apdu)
	if !ok || len(points) != 1 || points[0].Index != 0x0102 || points[0].Value != 1000 {
		t.Fatalf("ExtractAnalogOutputs = %v %+v, want ok=true {0x0102, 1000}", ok, points)
	}
}

func TestExtractAnalogOutputs_NotAnalog(t *testing.T) {
	t.Parallel()
	// A g12v1 CROB is not an analog output.
	points, ok := ExtractAnalogOutputs([]byte{GroupBinaryOutputControl, VarCROB, 0x17, 0x01, 0x00})
	if !ok || points != nil {
		t.Fatalf("ExtractAnalogOutputs on a CROB = %v %v, want (nil, true)", points, ok)
	}
}

func TestExtractAnalogOutputs_UnsupportedVariationFailsClosed(t *testing.T) {
	t.Parallel()
	if _, ok := ExtractAnalogOutputs([]byte{GroupAnalogOutput, 0x05, 0x17, 0x01, 0x00}); ok {
		t.Fatal("g41 variation 5 accepted; must fail closed")
	}
}

func TestExtractAnalogOutputs_TruncatedFailsClosed(t *testing.T) {
	t.Parallel()
	// Claims count=1 int32 but supplies only the index + 2 value bytes.
	apdu := []byte{GroupAnalogOutput, VarAnalogOutInt32, 0x17, 0x01, 0x09, 0x01, 0x02}
	if _, ok := ExtractAnalogOutputs(apdu); ok {
		t.Fatal("truncated analog output accepted; must fail closed")
	}
}
