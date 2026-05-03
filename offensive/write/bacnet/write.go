//go:build offensive

package bacnet

import (
	"crypto/sha256"
	"errors"
	"fmt"

	"local/elsereno/offensive/confirm"
)

// Op is a BACnet write kind. Only WriteProperty is implemented for
// F5; WritePropertyMultiple and TimeSynchronization follow in F6.
type Op string

// #nosec G101 -- false positive — op labels
const (
	// OpWriteProperty is BACnet Confirmed service 0x0F.
	OpWriteProperty Op = "write_property"
)

// ObjectType is a BACnet object type identifier (BACnet Std Annex H).
type ObjectType uint16

// Common object types that are targets of WriteProperty.
const (
	ObjectAnalogValue ObjectType = 2
	ObjectBinaryValue ObjectType = 5
	ObjectMultiState  ObjectType = 19
	ObjectDevice      ObjectType = 8
)

// Request is a single WriteProperty request.
type Request struct {
	Op         Op
	Target     string
	InvokeID   uint8
	ObjectType ObjectType
	Instance   uint32 // 22-bit range enforced by Build
	// PropertyID is the BACnet property id (e.g. 0x55 / 85 for
	// Present-Value, 0x4B / 75 for Object-Identifier).
	PropertyID uint16
	// Value is the pre-encoded application tag bytes (application
	// tag + value). The caller is responsible for encoding BACnet's
	// primitive tags — tooling lives in internal/protocols/bacnet
	// in F6.
	Value []byte
}

// Errors.
var (
	ErrBadOp              = errors.New("bacnet-write: unknown op")
	ErrEmptyValue         = errors.New("bacnet-write: value is empty")
	ErrInstanceTooLarge   = errors.New("bacnet-write: instance > 22 bits (0x3FFFFF)")
	ErrPropertyIDTooLarge = errors.New("bacnet-write: property id > 16 bits")
)

// Build returns the full BVLC datagram.
func Build(r Request) ([]byte, error) {
	if r.Op != OpWriteProperty {
		return nil, fmt.Errorf("%w: %q", ErrBadOp, r.Op)
	}
	if len(r.Value) == 0 {
		return nil, ErrEmptyValue
	}
	if r.Instance > 0x3FFFFF {
		return nil, ErrInstanceTooLarge
	}
	apdu := buildWritePropertyAPDU(r)
	npdu := []byte{
		0x01, // version
		0x04, // control: expect-reply=1
	}
	body := append([]byte{}, npdu...)
	body = append(body, apdu...)
	// BVLC: Type 0x81, Function 0x0A (Original-Unicast-NPDU),
	// Length (2 BE) includes the header itself (4).
	total := uint16(4 + len(body)) // #nosec G115 -- bounded
	return append([]byte{0x81, 0x0A, byte(total >> 8), byte(total & 0xFF)}, body...), nil
}

// #nosec G115 -- all byte conversions are bounded mask operations or range-guarded above
func buildWritePropertyAPDU(r Request) []byte {
	// APDU: PDU Type=0x00 (Confirmed Request), Max Seg/Response=0x05
	// (no segmentation, max APDU 1476), InvokeID, ServiceChoice=0x0F
	apdu := []byte{0x00, 0x05, r.InvokeID, 0x0F}

	// Context tag 0: Object Identifier (4 bytes) = 22-bit instance +
	// 10-bit object type, encoded as (objType << 22) | instance.
	objID := (uint32(r.ObjectType) << 22) | (r.Instance & 0x3FFFFF)
	tag0 := []byte{
		0x0C, // context tag 0, length=4
		byte(objID >> 24), byte(objID >> 16),
		byte(objID >> 8), byte(objID & 0xFF),
	}
	apdu = append(apdu, tag0...)

	// Context tag 1: Property Identifier (1 or 2 bytes).
	if r.PropertyID < 0x100 {
		apdu = append(apdu, 0x19, byte(r.PropertyID))
	} else {
		apdu = append(apdu, 0x1A, byte(r.PropertyID>>8), byte(r.PropertyID&0xFF))
	}

	// Context tag 3: Property Value (opening + pre-encoded value + closing).
	apdu = append(apdu, 0x3E) // opening tag 3
	apdu = append(apdu, r.Value...)
	apdu = append(apdu, 0x3F) // closing tag 3
	return apdu
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
		Protocol:    "bacnet",
		Operation:   string(r.Op),
		Target:      r.Target,
		PayloadHash: h,
	}, nil
}
