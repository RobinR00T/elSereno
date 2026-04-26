package wire

import "encoding/binary"

// ParseCreateObject extracts the requested ObjectType from a
// CreateObject confirmed-request APDU. Input is the APDU bytes
// AFTER the 4-byte confirmed-request header (the caller has
// already verified service choice == 10 via ParseAPDUHeader).
//
// CreateObject-Request layout (ASHRAE 135 §15.14):
//
//	[0] objectSpecifier  CHOICE {
//	      objectType        [0] BACnetObjectType,        (system picks instance)
//	      objectIdentifier  [1] BACnetObjectIdentifier   (operator picks both)
//	    }
//	[1] listOfInitialValues  SEQUENCE OF BACnetPropertyValue OPTIONAL
//
// Wire-level structure:
//
//	0x0E                                    open context tag 0 (constructed)
//	  one of:
//	    0x09 0xTT                           [0] objectType, length 1 (type ≤ 255)
//	    0x0A 0xTT 0xTT                      [0] objectType, length 2 (type 256..1023)
//	    0x1C 0xPP 0xPP 0xPP 0xPP            [1] objectIdentifier, length 4 packed
//	0x0F                                    close context tag 0
//	[ 0x1E ... 0x1F ]                       optional listOfInitialValues
//
// The v1.13 chunk-8 gate inspects only the ObjectType — even
// when the operator uses the [1] choice with a specific
// instance, the per-type allowlist matches by type alone. The
// v1.16 chunk-2 refinement adds a parallel per-(type, instance)
// allowlist; see ParseCreateObjectWithInstance for the richer
// shape.
//
// Returns (objType, true) on success, (0, false) on any parse
// error — the gate fails closed.
func ParseCreateObject(apdu []byte) (uint16, bool) {
	objType, _, _, ok := ParseCreateObjectWithInstance(apdu)
	return objType, ok
}

// ParseCreateObjectWithInstance extends ParseCreateObject by
// also returning the ObjectInstance (when present) plus a flag
// indicating which CHOICE the request used. v1.16 chunk 2:
// lets the gate scope CreateObject by (type, instance) when
// the ACS uses the [1] objectIdentifier form.
//
//   - CHOICE [0] objectType (`0x09` / `0x0A`): hasInstance=false,
//     instance=0. The device picks the instance — operators who
//     want exact-instance control must refuse this CHOICE
//     (handled at the gate layer, not here).
//   - CHOICE [1] objectIdentifier (`0x1C`): hasInstance=true,
//     instance is the lower-22-bits of the packed BACnet
//     ObjectIdentifier per ASHRAE 135 §13.2.
//
// Returns (0, 0, false, false) on any parse error.
func ParseCreateObjectWithInstance(apdu []byte) (objType uint16, instance uint32, hasInstance bool, ok bool) {
	if len(apdu) < 4 { // 0x0E + at least one tag byte + 1 value + 0x0F
		return 0, 0, false, false
	}
	if apdu[0] != 0x0E { // open context tag 0 (constructed)
		return 0, 0, false, false
	}
	rest := apdu[1:]
	objType, instance, hasInstance, consumed, ok := parseCreateObjectChoice(rest)
	if !ok {
		return 0, 0, false, false
	}
	rest = rest[consumed:]
	if len(rest) < 1 || rest[0] != 0x0F { // close context tag 0
		return 0, 0, false, false
	}
	return objType, instance, hasInstance, true
}

// parseCreateObjectChoice reads the inner CHOICE byte sequence
// and returns the resolved (BACnetObjectType, ObjectInstance,
// hasInstance, bytes-consumed, ok). The bytes-consumed value
// covers the choice tag + value bytes (NOT the trailing 0x0F
// close).
func parseCreateObjectChoice(b []byte) (objType uint16, instance uint32, hasInstance bool, consumed int, ok bool) {
	if len(b) < 1 {
		return 0, 0, false, 0, false
	}
	tag := b[0]
	switch tag {
	case 0x09: // [0] objectType, primitive, length 1 (type 0..255)
		if len(b) < 2 {
			return 0, 0, false, 0, false
		}
		return uint16(b[1]), 0, false, 2, true
	case 0x0A: // [0] objectType, primitive, length 2 (type 256..1023)
		if len(b) < 3 {
			return 0, 0, false, 0, false
		}
		v := binary.BigEndian.Uint16(b[1:3])
		// Validate the value fits in 10 bits per ASHRAE 135 §21.
		if v > 0x3FF {
			return 0, 0, false, 0, false
		}
		return v, 0, false, 3, true
	case 0x1C: // [1] objectIdentifier, primitive, length 4 (type+instance packed)
		if len(b) < 5 {
			return 0, 0, false, 0, false
		}
		raw := binary.BigEndian.Uint32(b[1:5])
		ot := uint16((raw >> 22) & 0x3FF)
		inst := raw & 0x3FFFFF
		return ot, inst, true, 5, true
	default:
		return 0, 0, false, 0, false
	}
}
