// Package wire parses BACnet/IP (ASHRAE 135) BVLC + NPDU + APDU
// frames. BACnet/IP runs on UDP/47808. ElSereno's probe sends an
// unicast Who-Is and classifies the I-Am response.
package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// BVLC is the Virtual Link Control header on every BACnet/IP frame.
// Layout: Type (1) Function (1) Length (2, BE).
type BVLC struct {
	Type     byte
	Function byte
	Length   uint16
}

// BVLC type and function constants.
const (
	BVLCTypeBacnetIP byte = 0x81

	BVLCOriginalUnicast   byte = 0x0A
	BVLCOriginalBroadcast byte = 0x0B
)

// ErrBadBVLC is returned when the header is malformed.
var ErrBadBVLC = errors.New("bacnet: bad BVLC")

// ParseBVLC parses the first 4 bytes of a BACnet/IP frame.
func ParseBVLC(b []byte) (BVLC, error) {
	if len(b) < 4 {
		return BVLC{}, fmt.Errorf("%w: %d bytes", ErrBadBVLC, len(b))
	}
	if b[0] != BVLCTypeBacnetIP {
		return BVLC{}, fmt.Errorf("%w: type=0x%02x", ErrBadBVLC, b[0])
	}
	h := BVLC{
		Type:     b[0],
		Function: b[1],
		Length:   binary.BigEndian.Uint16(b[2:4]),
	}
	if int(h.Length) != len(b) {
		return BVLC{}, fmt.Errorf("%w: length=%d, have %d", ErrBadBVLC, h.Length, len(b))
	}
	return h, nil
}

// BuildWhoIs returns a minimal Who-Is request (unconfirmed, no
// instance range) as an unicast broadcast. Total length 12 bytes.
func BuildWhoIs() []byte {
	// BVLC(4) + NPDU(2) + APDU(unconfirmed=0x10, service=0x08)
	return []byte{
		0x81, 0x0A, 0x00, 0x0C, // BVLC type, original-unicast, length=12
		0x01, 0x20, // NPDU version=1, control=0x20 (no dest, expect reply)
		0xFF, 0xFF, // ...broadcast network + hop count
		0x00, 0x00, // ...destination address (none)
		// simpler: use the common 0x81 0x0B variant; include minimal APDU
		0x10, 0x08, // APDU: unconfirmed, service 0x08 (Who-Is)
	}
}

// IsIAm reports whether body looks like an I-Am response to a Who-Is.
// Heuristic: APDU byte 0 == 0x10 (unconfirmed) and byte 1 == 0x00
// (I-Am service). Callers pass the bytes AFTER the 4-byte BVLC and
// the 2-byte NPDU.
func IsIAm(apdu []byte) bool {
	return len(apdu) >= 2 && apdu[0] == 0x10 && apdu[1] == 0x00
}
