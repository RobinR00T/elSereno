// Package wire parses DNP3 link-layer headers (IEEE 1815). The data
// link frame starts with 0x05 0x64 (start bytes), length, control,
// destination (2), source (2), CRC (2). ElSereno's probe sends
// link-layer Request Link Status frames (no application layer) and
// classifies the link-layer reply.
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

// RequestLinkStatusControl is the control octet of a master's Request
// Link Status: DIR=1, PRM=1, FCB=0, FCV=0, primary function 9.
const RequestLinkStatusControl = 0xC9

// SweepLastDest is the highest destination address the probe sweeps.
// An outstation only answers frames addressed to its own link address,
// which the scanner does not know, so the probe addresses 0..100 in one
// write, as nmap's dnp3-info.nse (DigitalBond Redpoint) does.
const SweepLastDest = 100

// BuildRequestLinkStatus returns a header-only Request Link Status frame
// (link function 9) from src to dest with its header CRC. It touches
// only the link layer: no application request is carried.
func BuildRequestLinkStatus(dest, src uint16) []byte {
	out := []byte{
		StartBytes[0], StartBytes[1],
		0x05, // length: control + dest + src, no user data
		RequestLinkStatusControl,
		0x00, 0x00, // dest
		0x00, 0x00, // src
		0x00, 0x00, // header CRC
	}
	binary.LittleEndian.PutUint16(out[4:6], dest)
	binary.LittleEndian.PutUint16(out[6:8], src)
	binary.LittleEndian.PutUint16(out[8:10], CRC16(out[0:8]))
	return out
}

// BuildLinkStatusSweep returns Request Link Status frames from src to
// every destination 0..last, concatenated for a single write. With
// src 0 and last SweepLastDest it reproduces the 101 frames of nmap's
// dnp3-info.nse (whose frame for destination 0x3D carries a typo and
// is malformed there; here it is well formed).
func BuildLinkStatusSweep(src, last uint16) []byte {
	out := make([]byte, 0, (int(last)+1)*HeaderLen)
	for dest := 0; dest <= int(last); dest++ {
		out = append(out, BuildRequestLinkStatus(uint16(dest), src)...) // #nosec G115 -- dest <= last, a uint16.
	}
	return out
}

// ValidHeader reports whether b starts with a well-formed link header:
// the 0x05 0x64 start octets, a length of at least 5 and a header CRC
// that matches. A real outstation always sends a correct CRC, and
// discards any frame whose CRC is wrong.
func ValidHeader(b []byte) bool {
	h, err := ParseHeader(b)
	return err == nil && CRC16(b[0:8]) == h.CRC
}
