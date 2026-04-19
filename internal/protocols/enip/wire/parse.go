package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// HeaderLen is the fixed EIP encapsulation header size.
const HeaderLen = 24

// MaxBodyLen is the Length field ceiling we accept.
const MaxBodyLen uint16 = 4096

// Command codes (ODVA CIP Vol 2 §2-3).
const (
	CmdListServices    uint16 = 0x0004
	CmdListIdentity    uint16 = 0x0063
	CmdListInterfaces  uint16 = 0x0064
	CmdRegisterSession uint16 = 0x0065
	CmdUnregisterSess  uint16 = 0x0066
	CmdSendRRData      uint16 = 0x006F
	CmdSendUnitData    uint16 = 0x0070
)

// ErrBadHeader is returned when the header is malformed or the length
// exceeds MaxBodyLen.
var ErrBadHeader = errors.New("enip: bad encapsulation header")

// Header is the decoded EIP encapsulation header.
type Header struct {
	Command       uint16
	Length        uint16
	SessionHandle uint32
	Status        uint32
	SenderContext [8]byte
	Options       uint32
}

// ParseHeader parses b into Header.
func ParseHeader(b []byte) (Header, error) {
	if len(b) < HeaderLen {
		return Header{}, fmt.Errorf("%w: %d bytes", ErrBadHeader, len(b))
	}
	h := Header{
		Command:       binary.LittleEndian.Uint16(b[0:2]),
		Length:        binary.LittleEndian.Uint16(b[2:4]),
		SessionHandle: binary.LittleEndian.Uint32(b[4:8]),
		Status:        binary.LittleEndian.Uint32(b[8:12]),
		Options:       binary.LittleEndian.Uint32(b[20:24]),
	}
	copy(h.SenderContext[:], b[12:20])
	if h.Length > MaxBodyLen {
		return Header{}, fmt.Errorf("%w: length=%d", ErrBadHeader, h.Length)
	}
	return h, nil
}

// MarshalHeader writes h into a 24-byte buffer.
func MarshalHeader(h Header) [HeaderLen]byte {
	var out [HeaderLen]byte
	binary.LittleEndian.PutUint16(out[0:2], h.Command)
	binary.LittleEndian.PutUint16(out[2:4], h.Length)
	binary.LittleEndian.PutUint32(out[4:8], h.SessionHandle)
	binary.LittleEndian.PutUint32(out[8:12], h.Status)
	copy(out[12:20], h.SenderContext[:])
	binary.LittleEndian.PutUint32(out[20:24], h.Options)
	return out
}

// BuildListIdentity returns a ListIdentity request (header + empty body).
func BuildListIdentity() []byte {
	h := Header{Command: CmdListIdentity}
	b := MarshalHeader(h)
	return b[:]
}

// ReadPacket reads one EIP packet (header + body) from r.
func ReadPacket(r io.Reader) (Header, []byte, error) {
	var hdrBuf [HeaderLen]byte
	if _, err := io.ReadFull(r, hdrBuf[:]); err != nil {
		return Header{}, nil, fmt.Errorf("enip: header: %w", err)
	}
	h, err := ParseHeader(hdrBuf[:])
	if err != nil {
		return Header{}, nil, err
	}
	body := make([]byte, h.Length)
	if h.Length > 0 {
		if _, err := io.ReadFull(r, body); err != nil {
			return Header{}, nil, fmt.Errorf("enip: body: %w", err)
		}
	}
	return h, body, nil
}

// IdentityItem is the CIP Identity Object summary carried in a
// ListIdentity reply's item data.
type IdentityItem struct {
	VendorID     uint16
	DeviceType   uint16
	ProductCode  uint16
	Revision     uint16 // major<<8 | minor
	Status       uint16
	SerialNumber uint32
	ProductName  string
}

// ParseListIdentity extracts at least one IdentityItem from a
// ListIdentity reply body. Malformed replies return an error.
func ParseListIdentity(body []byte) (IdentityItem, error) {
	// Body: ItemCount (2) [ID(2) Length(2) TypeCode(2) EncapProto(2)
	// SockaddrFamily(2) Port(2) Addr(4) ZeroPad(8) VendorID(2)
	// DeviceType(2) ProductCode(2) Revision(2) Status(2)
	// SerialNumber(4) NameLen(1) Name(N) State(1)]
	if len(body) < 2 {
		return IdentityItem{}, errors.New("enip: list-identity: too short")
	}
	count := binary.LittleEndian.Uint16(body[0:2])
	if count == 0 {
		return IdentityItem{}, errors.New("enip: list-identity: 0 items")
	}
	// Offset of VendorID: after ItemCount(2) + ItemType(2) +
	// ItemLength(2) + EncapProto(2) + Sockaddr(16) = 24.
	off := 2 + 4 + 2 + 16
	// Fixed fields from VendorID..NameLen = 14 + 1 = 15 bytes.
	if len(body) < off+15 {
		return IdentityItem{}, errors.New("enip: list-identity: truncated body")
	}
	it := IdentityItem{
		VendorID:     binary.LittleEndian.Uint16(body[off : off+2]),
		DeviceType:   binary.LittleEndian.Uint16(body[off+2 : off+4]),
		ProductCode:  binary.LittleEndian.Uint16(body[off+4 : off+6]),
		Revision:     uint16(body[off+6])<<8 | uint16(body[off+7]),
		Status:       binary.LittleEndian.Uint16(body[off+8 : off+10]),
		SerialNumber: binary.LittleEndian.Uint32(body[off+10 : off+14]),
	}
	nameLen := int(body[off+14])
	// Need nameLen bytes after NameLen (at off+15).
	if len(body) < off+15+nameLen {
		return IdentityItem{}, errors.New("enip: list-identity: truncated product name")
	}
	it.ProductName = string(body[off+15 : off+15+nameLen])
	return it, nil
}
