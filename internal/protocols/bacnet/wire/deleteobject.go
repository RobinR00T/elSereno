package wire

// ObjectIdentifier is a parsed BACnet object identity (type +
// instance). The 10-bit object type + 22-bit instance pair lives
// in a single 4-byte word per ASHRAE 135 §21.
//
// Re-used across object-level services (DeleteObject svc 11,
// CreateObject svc 10's [1] choice, etc.) where there's no
// PropertyIdentifier dimension.
type ObjectIdentifier struct {
	ObjectType     uint16
	ObjectInstance uint32
}

// ParseDeleteObject extracts the target object identity from a
// DeleteObject confirmed-request APDU. Input is the APDU bytes
// AFTER the 4-byte confirmed-request header (the caller has
// already verified service choice == 11).
//
// DeleteObject-Request layout (ASHRAE 135 §15.3):
//
//	[0] BACnetObjectIdentifier      context tag 0, length 4
//
// Just one operand; no property field, no list. The encoded
// form is the same 5-byte sequence as the first field of
// WriteProperty (`0x0C` + 4 packed bytes), so we reuse the
// existing readObjectID helper.
//
// Returns (id, true) on success, (_, false) on any parse
// error — the gate fails closed.
func ParseDeleteObject(apdu []byte) (ObjectIdentifier, bool) {
	objType, objInst, _, ok := readObjectID(apdu)
	if !ok {
		return ObjectIdentifier{}, false
	}
	return ObjectIdentifier{
		ObjectType:     objType,
		ObjectInstance: objInst,
	}, true
}
