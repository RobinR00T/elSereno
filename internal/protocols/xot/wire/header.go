package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Version is the XOT protocol version byte value; RFC 1613 section 2.3
// specifies two zero bytes.
const Version uint16 = 0x0000

// HeaderLen is the fixed XOT TCP header length in bytes.
const HeaderLen = 4

// MaxPayloadLen is the RFC 1613 maximum X.25 payload length in bytes.
const MaxPayloadLen = 4096

// MinPayloadLen is the smallest legal X.25 packet (GFI+LCN+PTI).
const MinPayloadLen = 3

// ErrBadVersion is returned when the XOT version field is non-zero.
var ErrBadVersion = errors.New("xot: invalid version")

// ErrPayloadTooLong is returned when the length field exceeds
// MaxPayloadLen.
var ErrPayloadTooLong = errors.New("xot: payload exceeds RFC 1613 maximum of 4096 bytes")

// ErrPayloadTooShort is returned when the length field is smaller
// than MinPayloadLen.
var ErrPayloadTooShort = errors.New("xot: payload shorter than the minimum 3 bytes")

// Header is the decoded XOT envelope.
type Header struct {
	Version uint16
	Length  uint16
}

// ReadHeader reads 4 bytes from r and decodes the XOT header. It
// validates Version and Length.
func ReadHeader(r io.Reader) (Header, error) {
	var b [HeaderLen]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return Header{}, fmt.Errorf("xot: header: %w", err)
	}
	return ParseHeader(b[:])
}

// ParseHeader parses 4 bytes as an XOT header without consuming them
// from a reader.
func ParseHeader(b []byte) (Header, error) {
	if len(b) < HeaderLen {
		return Header{}, fmt.Errorf("xot: header: %w", io.ErrUnexpectedEOF)
	}
	v := binary.BigEndian.Uint16(b[0:2])
	l := binary.BigEndian.Uint16(b[2:4])
	if v != Version {
		return Header{}, fmt.Errorf("%w: 0x%04x", ErrBadVersion, v)
	}
	if l > MaxPayloadLen {
		return Header{}, fmt.Errorf("%w: %d", ErrPayloadTooLong, l)
	}
	if l < MinPayloadLen {
		return Header{}, fmt.Errorf("%w: %d", ErrPayloadTooShort, l)
	}
	return Header{Version: v, Length: l}, nil
}

// MarshalHeader writes h into a fixed 4-byte buffer.
func MarshalHeader(h Header) [HeaderLen]byte {
	var out [HeaderLen]byte
	binary.BigEndian.PutUint16(out[0:2], h.Version)
	binary.BigEndian.PutUint16(out[2:4], h.Length)
	return out
}
