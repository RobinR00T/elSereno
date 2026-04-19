// Package wire parses the HART-IP (FCG TS20085) fixed 8-byte
// header. Layout: Version (1) + MessageType (1) + MessageID (1) +
// Status (1) + SequenceNumber (2 BE) + ByteCount (2 BE).
package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// HeaderLen is the fixed HART-IP header size.
const HeaderLen = 8

// Version is the current HART-IP protocol version we expect.
const Version uint8 = 1

// MessageType values.
const (
	MsgRequest  = 0x00
	MsgResponse = 0x01
)

// MessageID values (subset).
const (
	IDSessionInitiate = 0x00
	IDSessionClose    = 0x01
	IDKeepAlive       = 0x02
	IDTokenPassPDU    = 0x03
)

// ErrBadHeader is returned when the header is malformed.
var ErrBadHeader = errors.New("hartip: bad header")

// Header is the parsed HART-IP header.
type Header struct {
	Version   uint8
	MsgType   uint8
	MsgID     uint8
	Status    uint8
	Sequence  uint16
	ByteCount uint16
}

// ParseHeader parses the 8-byte header.
func ParseHeader(b []byte) (Header, error) {
	if len(b) < HeaderLen {
		return Header{}, fmt.Errorf("%w: %d bytes", ErrBadHeader, len(b))
	}
	h := Header{
		Version:   b[0],
		MsgType:   b[1],
		MsgID:     b[2],
		Status:    b[3],
		Sequence:  binary.BigEndian.Uint16(b[4:6]),
		ByteCount: binary.BigEndian.Uint16(b[6:8]),
	}
	if h.Version != Version {
		return Header{}, fmt.Errorf("%w: version %d", ErrBadHeader, h.Version)
	}
	if int(h.ByteCount) < HeaderLen {
		return Header{}, fmt.Errorf("%w: byte count %d < header", ErrBadHeader, h.ByteCount)
	}
	return h, nil
}

// BuildSessionInitiate returns a session-initiate request body
// (header + 5-byte "PrimaryMaster + InactivityClose" payload).
func BuildSessionInitiate(seq uint16) []byte {
	payload := []byte{0x01, 0x00, 0x00, 0x00, 0x00}
	out := make([]byte, HeaderLen+len(payload))
	out[0] = Version
	out[1] = MsgRequest
	out[2] = IDSessionInitiate
	out[3] = 0x00
	binary.BigEndian.PutUint16(out[4:6], seq)
	// #nosec G115 -- len(payload)+HeaderLen fits in uint16 (HeaderLen=8, payload small)
	binary.BigEndian.PutUint16(out[6:8], uint16(HeaderLen+len(payload)))
	copy(out[HeaderLen:], payload)
	return out
}
