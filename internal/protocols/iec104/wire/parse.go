// Package wire parses IEC 60870-5-104 APCI frames. APCI layout
// (IEC 60870-5-104 §5.1): Start (1, 0x68) + APDULength (1) +
// Control (4).
package wire

import (
	"errors"
	"fmt"
)

// Start is the IEC 60870-5-104 start byte.
const Start byte = 0x68

// APCILen is the fixed APCI header size.
const APCILen = 6

// ErrBadStart is returned when the first byte is not 0x68.
var ErrBadStart = errors.New("iec104: bad start byte")

// ErrBadLength is returned when APDULength is outside [4, 253].
var ErrBadLength = errors.New("iec104: bad apdu length")

// APCI holds the parsed header. Frame types are inferred from the
// low two bits of Control[0]:
//
//	00 -> I-format (information transfer)
//	01 -> S-format (supervisory)
//	11 -> U-format (unnumbered)
type APCI struct {
	Length  uint8
	Control [4]byte
}

// FrameType is a human-readable frame kind.
type FrameType string

// Frame types.
const (
	FrameI       FrameType = "I"
	FrameS       FrameType = "S"
	FrameU       FrameType = "U"
	FrameUnknown FrameType = "?"
)

// ParseAPCI parses the 6-byte APCI.
func ParseAPCI(b []byte) (APCI, error) {
	if len(b) < APCILen {
		return APCI{}, fmt.Errorf("%w: %d bytes", ErrBadStart, len(b))
	}
	if b[0] != Start {
		return APCI{}, ErrBadStart
	}
	if b[1] < 4 || b[1] > 253 {
		return APCI{}, fmt.Errorf("%w: %d", ErrBadLength, b[1])
	}
	a := APCI{Length: b[1]}
	copy(a.Control[:], b[2:6])
	return a, nil
}

// Type returns the APCI frame type.
func (a APCI) Type() FrameType {
	switch a.Control[0] & 0x03 {
	case 0x00, 0x02:
		return FrameI
	case 0x01:
		return FrameS
	case 0x03:
		return FrameU
	}
	return FrameUnknown
}

// BuildTESTFR returns a TESTFR act U-format frame (Control 0x43 per
// spec): bit 0,1 = 11 (U-format), bits 2-7 = 010000 act test.
func BuildTESTFR() []byte {
	return []byte{Start, 0x04, 0x43, 0x00, 0x00, 0x00}
}

// BuildSTARTDT returns a STARTDT act frame (Control 0x07).
func BuildSTARTDT() []byte {
	return []byte{Start, 0x04, 0x07, 0x00, 0x00, 0x00}
}
