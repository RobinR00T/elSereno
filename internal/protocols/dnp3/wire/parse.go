// Package wire parses DNP3 link-layer headers (IEEE 1815). The data
// link frame starts with 0x05 0x64 (start bytes), length, control,
// destination (2), source (2), CRC (2). ElSereno's probe sends a
// minimal Read Class 0 request and classifies the application-layer
// reply.
package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// StartBytes is the DNP3 data-link frame prefix.
var StartBytes = [2]byte{0x05, 0x64}

// HeaderLen is the fixed link-layer header: 2 start + 1 length + 1
// control + 2 dest + 2 src + 2 CRC.
const HeaderLen = 10

// ErrBadStart is returned when the start bytes do not match 0x05 0x64.
var ErrBadStart = errors.New("dnp3: bad start bytes")

// ErrBadLength is returned when the length field is outside [5, 255].
var ErrBadLength = errors.New("dnp3: bad length")

// Header is the parsed link-layer header.
type Header struct {
	Length  uint8
	Control uint8
	Dest    uint16
	Src     uint16
	CRC     uint16
}

// ParseHeader parses the first 10 bytes.
func ParseHeader(b []byte) (Header, error) {
	if len(b) < HeaderLen {
		return Header{}, fmt.Errorf("%w: %d bytes", ErrBadStart, len(b))
	}
	if b[0] != StartBytes[0] || b[1] != StartBytes[1] {
		return Header{}, ErrBadStart
	}
	h := Header{
		Length:  b[2],
		Control: b[3],
		Dest:    binary.LittleEndian.Uint16(b[4:6]),
		Src:     binary.LittleEndian.Uint16(b[6:8]),
		CRC:     binary.LittleEndian.Uint16(b[8:10]),
	}
	if h.Length < 5 {
		return Header{}, fmt.Errorf("%w: %d", ErrBadLength, h.Length)
	}
	return h, nil
}

// BuildReadClass0 returns a minimal Read Class 0 frame. Note this is
// the simplest "speak DNP3 at me" probe and not a full IEEE 1815
// implementation; callers that want correct CRC-16 should compute it.
// For the ElSereno fingerprint we rely on the response start-byte
// match rather than strict CRC validation.
func BuildReadClass0(dest, src uint16) []byte {
	out := []byte{
		StartBytes[0], StartBytes[1],
		0x05,       // length (arbitrary short)
		0xC4,       // control: DIR=1, PRM=1, FCB=0, FCV=0, function 4 (Unconfirmed User Data)
		0x00, 0x00, // dest
		0x00, 0x00, // src
		0x00, 0x00, // CRC placeholder
	}
	binary.LittleEndian.PutUint16(out[4:6], dest)
	binary.LittleEndian.PutUint16(out[6:8], src)
	return out
}

// IsDNP3Frame returns true if b begins with 0x05 0x64.
func IsDNP3Frame(b []byte) bool {
	return len(b) >= 2 && b[0] == StartBytes[0] && b[1] == StartBytes[1]
}
