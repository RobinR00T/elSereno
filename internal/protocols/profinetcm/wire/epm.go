package wire

import (
	"encoding/binary"
	"errors"
	"strings"
)

// Port is the PNIO-CM (DCE/RPC) UDP port.
const Port = 34964

// DCE/RPC CL packet types used here.
const (
	PTypeRequest  byte = 0
	PTypeResponse byte = 2
	PTypeFault    byte = 3
	PTypeReject   byte = 6
)

const (
	headerLen  = 80
	opLookup   = 2
	ndrLittle  = 0x10 // drep[0]: little-endian integers, ASCII
	annotStart = headerLen + 20 + 4 + 12 + 16 + 4
)

var (
	// epmInterface is e1af8308-5d1f-11c9-91a4-08002b14a0fa, little-endian
	// field order as sent on the wire with drep 0x10.
	epmInterface = [16]byte{0x08, 0x83, 0xaf, 0xe1, 0x1f, 0x5d, 0xc9, 0x11, 0x91, 0xa4, 0x08, 0x00, 0x2b, 0x14, 0xa0, 0xfa}
	// pnioDevice is dea00001-6c97-11d1-8271-00a02442df7d.
	pnioDevice = [16]byte{0x01, 0x00, 0xa0, 0xde, 0x97, 0x6c, 0xd1, 0x11, 0x82, 0x71, 0x00, 0xa0, 0x24, 0x42, 0xdf, 0x7d}
)

// Errors.
var (
	ErrShort       = errors.New("profinet-cm: reply too short")
	ErrNotDCERPC   = errors.New("profinet-cm: not a DCE/RPC CL v4 packet")
	ErrActivity    = errors.New("profinet-cm: reply activity id differs from the request")
	ErrNotResponse = errors.New("profinet-cm: not an EPM lookup response")
	ErrNoEntry     = errors.New("profinet-cm: lookup returned no entry")
)

// BuildLookup returns an EPM ept_lookup request for the PNIO device
// interface, max one entry, under the given activity id.
func BuildLookup(activity [16]byte) []byte {
	b := make([]byte, headerLen, headerLen+76)
	b[0], b[1], b[2], b[4] = 4, PTypeRequest, 0x20, ndrLittle // version 4, request, idempotent
	copy(b[24:40], epmInterface[:])
	copy(b[40:56], activity[:])
	binary.LittleEndian.PutUint32(b[60:], 3) // EPM interface version
	binary.LittleEndian.PutUint16(b[68:], opLookup)
	binary.LittleEndian.PutUint16(b[70:], 0xffff)    // interface hint
	binary.LittleEndian.PutUint16(b[72:], 0xffff)    // activity hint
	binary.LittleEndian.PutUint16(b[74:], 76)        // body length
	body := binary.LittleEndian.AppendUint32(nil, 0) // inquiry type: all elements
	body = binary.LittleEndian.AppendUint32(body, 1) // object pointer
	body = append(body, make([]byte, 16)...)         // nil object UUID
	body = binary.LittleEndian.AppendUint32(body, 2) // interface pointer
	body = append(body, pnioDevice[:]...)
	body = binary.LittleEndian.AppendUint16(body, 1) // version major
	body = binary.LittleEndian.AppendUint16(body, 0) // version minor
	body = binary.LittleEndian.AppendUint32(body, 1) // version option: all
	body = append(body, make([]byte, 20)...)         // entry handle
	body = binary.LittleEndian.AppendUint32(body, 1) // max entries
	return append(b, body...)
}

// Reply is the classified answer.
type Reply struct {
	PType      byte   `json:"ptype"`
	Annotation string `json:"annotation,omitempty"`
	DeviceType string `json:"device_type,omitempty"`
	OrderID    string `json:"order_id,omitempty"`
	HWRevision string `json:"hw_revision,omitempty"`
	SWRevision string `json:"sw_revision,omitempty"`
}

// Classify checks that b is a DCE/RPC CL v4 packet for our activity and,
// for a response, decodes the first entry's annotation. A fault or reject
// is returned with no error: it still proves a DCE/RPC endpoint.
func Classify(b []byte, activity [16]byte) (Reply, error) {
	if len(b) < headerLen {
		return Reply{}, ErrShort
	}
	if b[0] != 4 {
		return Reply{}, ErrNotDCERPC
	}
	if [16]byte(b[40:56]) != activity {
		return Reply{}, ErrActivity
	}
	r := Reply{PType: b[1]}
	switch r.PType {
	case PTypeFault, PTypeReject:
		return r, nil
	case PTypeResponse:
	default:
		return Reply{}, ErrNotResponse
	}
	var bo binary.ByteOrder = binary.BigEndian
	if b[4]&0xf0 == ndrLittle {
		bo = binary.LittleEndian
	}
	if len(b) < annotStart+8 {
		return Reply{}, ErrShort
	}
	if bo.Uint32(b[headerLen+20:]) == 0 {
		return Reply{}, ErrNoEntry
	}
	n := int(bo.Uint32(b[annotStart+4:]))
	if n <= 0 || n > 64 || annotStart+8+n > len(b) {
		return Reply{}, ErrShort
	}
	r.Annotation = printable(b[annotStart+8 : annotStart+8+n])
	r.DeviceType, r.OrderID, r.HWRevision, r.SWRevision = splitAnnotation(r.Annotation)
	return r, nil
}

// splitAnnotation cuts the fixed-width PNIO annotation: device type (25),
// order id (20), hardware revision (5), software revision (rest), each
// separated by one space.
func splitAnnotation(a string) (typ, order, hw, sw string) {
	field := func(from, to int) string {
		if from >= len(a) {
			return ""
		}
		return strings.TrimSpace(a[from:min(to, len(a))])
	}
	return field(0, 25), field(26, 46), field(47, 52), field(53, len(a))
}

func printable(b []byte) string {
	var s strings.Builder
	for _, c := range b {
		if c == 0 {
			break
		}
		if c >= 0x20 && c < 0x7f {
			s.WriteByte(c)
		}
	}
	return strings.TrimRight(s.String(), " ")
}
