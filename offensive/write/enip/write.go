//go:build offensive

package enip

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	enipwire "local/elsereno/internal/protocols/enip/wire"
	"local/elsereno/offensive/confirm"
)

// Op enumerates the CIP write operations.
type Op string

// #nosec G101 -- false positive — op labels
const (
	// OpSetAttributeSingle is CIP service 0x10 Set Attribute Single.
	OpSetAttributeSingle Op = "set_attribute_single"
	// OpReset is CIP service 0x05 Reset (identity object 0x01).
	OpReset Op = "reset"
)

// Request is a CIP write issued over an EtherNet/IP session.
type Request struct {
	Op            Op
	Target        string
	SessionHandle uint32 // from a prior RegisterSession
	SenderContext [8]byte
	ClassID       uint16 // default 0x01 (Identity) for Reset
	InstanceID    uint16 // default 0x01
	AttributeID   uint16 // only for SetAttributeSingle
	Data          []byte // only for SetAttributeSingle
}

// Errors.
var (
	ErrBadOp = errors.New("enip-write: unknown op")
)

// Build returns the full EIP encapsulation packet (ready to write on
// an established EIP session).
func Build(r Request) ([]byte, error) {
	switch r.Op {
	case OpSetAttributeSingle:
		return buildSetAttribute(r), nil
	case OpReset:
		return buildReset(r), nil
	default:
		return nil, fmt.Errorf("%w: %q", ErrBadOp, r.Op)
	}
}

// MutationFor constructs the confirm.Mutation for r.
func MutationFor(r Request) (confirm.Mutation, error) {
	pkt, err := Build(r)
	if err != nil {
		return confirm.Mutation{}, err
	}
	h := sha256.Sum256(pkt)
	return confirm.Mutation{
		Category:    confirm.CategoryWrite,
		Protocol:    "enip",
		Operation:   string(r.Op),
		Target:      r.Target,
		PayloadHash: h,
	}, nil
}

// #nosec G115 -- epath length is bounded by the fixed EPATH segment layout above
func buildSetAttribute(r Request) []byte {
	// CIP EPATH: class+instance+attribute (8/16-bit segments).
	// For simplicity use 16-bit for each: 0x21, 0x00, class(LE16),
	// 0x25, 0x00, instance(LE16), 0x30, 0x00, attr(LE16).
	epath := []byte{
		0x21, 0x00,
		byte(r.ClassID & 0xFF), byte(r.ClassID >> 8),
		0x25, 0x00,
		byte(r.InstanceID & 0xFF), byte(r.InstanceID >> 8),
		0x30, 0x00,
		byte(r.AttributeID & 0xFF), byte(r.AttributeID >> 8),
	}
	// MessageRouter request: service(1) + pathSize(1 word count) +
	// path + data
	pathWords := uint8(len(epath) / 2)
	mr := append([]byte{0x10, pathWords}, epath...)
	mr = append(mr, r.Data...)
	return wrapSendRRData(r, mr)
}

// #nosec G115 -- fixed-size EPATH
func buildReset(r Request) []byte {
	// Reset service uses class 0x01 Identity instance 0x01 with no
	// data.
	class := r.ClassID
	if class == 0 {
		class = 0x0001
	}
	instance := r.InstanceID
	if instance == 0 {
		instance = 0x0001
	}
	epath := []byte{
		0x21, 0x00,
		byte(class & 0xFF), byte(class >> 8),
		0x25, 0x00,
		byte(instance & 0xFF), byte(instance >> 8),
	}
	pathWords := uint8(len(epath) / 2)
	mr := append([]byte{0x05, pathWords}, epath...)
	return wrapSendRRData(r, mr)
}

// wrapSendRRData wraps the MR payload in the Unconnected CPF +
// SendRRData encapsulation.
//
// #nosec G115 -- MR size bounded by caller (Set/Reset PDU)
func wrapSendRRData(r Request, mr []byte) []byte {
	// CPF layout: ItemCount=2 + [NullAddr(2+2) + UnconnData(2+2+mr)]
	cpf := []byte{
		0x02, 0x00, // ItemCount=2
		0x00, 0x00, // Type ID 0x0000 (Null address)
		0x00, 0x00, // Length 0
		0xB2, 0x00, // Type ID 0x00B2 (Unconnected Data)
		byte(len(mr) & 0xFF), byte(len(mr) >> 8),
	}
	cpf = append(cpf, mr...)
	// SendRRData data = InterfaceHandle(4 LE)=0 + Timeout(2 LE)=10 + CPF
	body := []byte{0x00, 0x00, 0x00, 0x00, 0x0A, 0x00}
	body = append(body, cpf...)

	// Encapsulation header.
	hdr := enipwire.Header{
		Command:       enipwire.CmdSendRRData,
		Length:        uint16(len(body)), // #nosec G115 -- bounded by fixtures
		SessionHandle: r.SessionHandle,
		SenderContext: r.SenderContext,
	}
	out := enipwire.MarshalHeader(hdr)
	// out is [24]byte array; we need to re-assemble with the body
	// appended AND the Length field already set by MarshalHeader.
	buf := make([]byte, 0, enipwire.HeaderLen+len(body))
	buf = append(buf, out[:]...)
	// Rewrite Length in the header copy we just emitted to be
	// safe (MarshalHeader already did it, but double-check).
	binary.LittleEndian.PutUint16(buf[2:4], uint16(len(body))) // #nosec G115 -- bounded by fixtures
	buf = append(buf, body...)
	return buf
}
