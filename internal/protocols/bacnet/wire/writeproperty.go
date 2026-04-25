package wire

import (
	"encoding/binary"
)

// WritePropertyTarget is the parsed ObjectIdentifier +
// PropertyIdentifier from a WriteProperty service request. The
// gate uses it for the per-object allowlist check (v1.12 chunk
// 7). ObjectType is 10 bits (0..1023) and ObjectInstance is 22
// bits (0..4_194_303) per ASHRAE 135 §21; PropertyID is a BACnet
// PropertyIdentifier enum (up to ~4096 today).
type WritePropertyTarget struct {
	ObjectType     uint16
	ObjectInstance uint32
	PropertyID     uint32
}

// ParseWriteProperty extracts the (ObjectID, PropertyID) from a
// WriteProperty confirmed-request APDU. Input is the APDU bytes
// AFTER the 4-byte confirmed-request header (the operator has
// already verified service choice == 15 via ParseAPDUHeader).
//
// WriteProperty-Request layout (ASHRAE 135 §15.9 + §20.2):
//
//	[0]  BACnetObjectIdentifier   context tag 0, length 4
//	[1]  BACnetPropertyIdentifier context tag 1, length 1..3
//	[2]  PropertyArrayIndex      context tag 2 (OPTIONAL)
//	[3]  PropertyValue            context tag 3 (opening/closing)
//	[4]  Priority                 context tag 4 (OPTIONAL)
//
// Only tags 0 and 1 are needed by the gate; later tags are
// walked over / skipped. Returns (target, true) on success,
// (_, false) on any parse error — caller fails closed.
//
// v1.12 chunk 7: covers service 15 WriteProperty only. The
// analogous per-object gate for WritePropertyMultiple
// (service 16) and list-mutation services (8, 9) is a v1.13+
// follow-up.
func ParseWriteProperty(apdu []byte) (WritePropertyTarget, bool) {
	// Skip the 4-byte confirmed-request header: caller positioned
	// us at the service-request body.
	body := apdu
	off := 0

	// Tag 0: ObjectIdentifier (4 bytes BACnetObjectId).
	objType, objInst, consumed, ok := readObjectID(body[off:])
	if !ok {
		return WritePropertyTarget{}, false
	}
	off += consumed

	// Tag 1: PropertyIdentifier (unsigned 1..3 bytes).
	propID, consumed, ok := readPropertyID(body[off:])
	if !ok {
		return WritePropertyTarget{}, false
	}
	_ = off + consumed // remaining tags skipped; gate only needs 0+1

	return WritePropertyTarget{
		ObjectType:     objType,
		ObjectInstance: objInst,
		PropertyID:     propID,
	}, true
}

// readObjectID reads a context-tag-0 BACnetObjectIdentifier
// (tag byte 0x0C + 4 data bytes). Returns (type, instance,
// bytes-consumed, ok). Fails if the tag byte isn't context-0
// length-4 or the 4 data bytes are truncated.
//
// Tag byte 0x0C layout per ASHRAE 135 §20.2.1.3.1:
//
//	bits 7..4 = 0000 (tag number 0)
//	bit  3    = 1    (class = context)
//	bits 2..0 = 100  (length = 4)
func readObjectID(b []byte) (uint16, uint32, int, bool) {
	if len(b) < 5 {
		return 0, 0, 0, false
	}
	if b[0] != 0x0C {
		return 0, 0, 0, false
	}
	raw := binary.BigEndian.Uint32(b[1:5])
	// Type: high 10 bits; Instance: low 22 bits.
	objType := uint16((raw >> 22) & 0x3FF)
	objInst := raw & 0x3FFFFF
	return objType, objInst, 5, true
}

// readPropertyID reads a context-tag-1 BACnetPropertyIdentifier.
// PropertyIdentifier is an enumerated up to a few hundred today
// (ASHRAE 135 Table 12-N, up to ~4000 reserved). Encoded as an
// unsigned of 1..3 bytes inside a context-tag-1 wrapper.
//
// Tag byte layout:
//
//	bits 7..4 = 0001 (tag number 1)
//	bit  3    = 1    (class = context)
//	bits 2..0 = length (1..3)
//
// Valid tag bytes: 0x19 (length 1), 0x1A (length 2), 0x1B
// (length 3). Returns (id, bytes-consumed, ok).
func readPropertyID(b []byte) (uint32, int, bool) {
	if len(b) < 1 {
		return 0, 0, false
	}
	tag := b[0]
	// Upper nibble must be 0001 (tag 1); bit 3 must be 1 (context).
	if tag&0xF8 != 0x18 {
		return 0, 0, false
	}
	ln := int(tag & 0x07)
	if ln < 1 || ln > 3 {
		return 0, 0, false
	}
	if len(b) < 1+ln {
		return 0, 0, false
	}
	var id uint32
	for i := 0; i < ln; i++ {
		id = (id << 8) | uint32(b[1+i])
	}
	return id, 1 + ln, true
}
