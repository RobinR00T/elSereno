package wire

// ParseWritePropertyMultiple walks a WritePropertyMultiple
// service request (ASHRAE 135 §15.10) and returns one
// WritePropertyTarget per (ObjectIdentifier, PropertyIdentifier)
// pair across the entire `listOfWriteAccessSpecifications`.
//
// Wire layout (after the 4-byte confirmed-request header):
//
//	WritePropertyMultiple-Request ::=
//	  SEQUENCE OF WriteAccessSpecification
//
//	WriteAccessSpecification ::= SEQUENCE {
//	  objectIdentifier  [0] BACnetObjectIdentifier,
//	  listOfProperties  [1] SEQUENCE OF BACnetPropertyValue
//	}
//
//	BACnetPropertyValue ::= SEQUENCE {
//	  propertyIdentifier  [0] BACnetPropertyIdentifier,
//	  propertyArrayIndex  [1] Unsigned OPTIONAL,
//	  value               [2] ABSTRACT-SYNTAX.&Type,    -- any
//	  priority            [3] Unsigned (1..16) OPTIONAL
//	}
//
// Tag bytes (ASHRAE 135 §20.2.1.3.1):
//
//	0x0C   context 0, primitive, length 4   ObjectIdentifier
//	0x1E   context 1, opening               listOfProperties opens
//	0x1F   context 1, closing               listOfProperties closes
//	0x09…  context 0, primitive, length 1..3   PropertyIdentifier
//	0x19…  context 1, primitive, length 1..3   PropertyArrayIndex
//	0x2E   context 2, opening               value opens
//	0x2F   context 2, closing               value closes
//	0x39…  context 3, primitive, length 1   Priority
//
// Returns (nil, false) on any parse error — caller fails closed.
//
// Empty list (zero WriteAccessSpecifications) returns (nil,
// false) so the gate refuses an "empty" WritePropertyMultiple
// rather than letting it slip through.
func ParseWritePropertyMultiple(apdu []byte) ([]WritePropertyTarget, bool) {
	out := make([]WritePropertyTarget, 0, 4)
	off := 0
	for off < len(apdu) {
		consumed, targets, ok := parseWriteAccessSpec(apdu[off:])
		if !ok {
			return nil, false
		}
		out = append(out, targets...)
		off += consumed
	}
	if len(out) == 0 {
		return nil, false
	}
	return out, true
}

// parseWriteAccessSpec walks one `WriteAccessSpecification`
// entry: a tag-0 ObjectIdentifier + a tag-1 opening/closing
// list of BACnetPropertyValue. Returns the bytes consumed +
// one WritePropertyTarget per property in the inner list.
func parseWriteAccessSpec(b []byte) (int, []WritePropertyTarget, bool) {
	off := 0

	// Tag 0: BACnetObjectIdentifier (5 bytes).
	objType, objInst, consumed, ok := readObjectID(b[off:])
	if !ok {
		return 0, nil, false
	}
	off += consumed

	// Tag 1 OPENING (0x1E): listOfProperties starts.
	if off >= len(b) || b[off] != 0x1E {
		return 0, nil, false
	}
	off++

	// Inner loop: each BACnetPropertyValue until we hit the
	// matching tag-1 CLOSING (0x1F).
	out := make([]WritePropertyTarget, 0, 4)
	for {
		if off >= len(b) {
			return 0, nil, false
		}
		if b[off] == 0x1F {
			off++
			return off, out, true
		}
		consumed, propID, ok := parseInnerPropertyValue(b[off:])
		if !ok {
			return 0, nil, false
		}
		out = append(out, WritePropertyTarget{
			ObjectType:     objType,
			ObjectInstance: objInst,
			PropertyID:     propID,
		})
		off += consumed
	}
}

// parseInnerPropertyValue walks one BACnetPropertyValue:
// tag 0 PropertyIdentifier (required) + optional tag 1
// PropertyArrayIndex + tag 2 opening/closing value + optional
// tag 3 Priority. Returns bytes consumed + the property ID.
//
// The PropertyIdentifier wrapper differs from the
// WriteProperty case: BACnetPropertyValue carries it under
// CONTEXT TAG 0 (tag bytes 0x09 / 0x0A / 0x0B), while
// WriteProperty uses CONTEXT TAG 1 (0x19 / 0x1A / 0x1B). We
// can't reuse readPropertyID here.
func parseInnerPropertyValue(b []byte) (int, uint32, bool) {
	off := 0

	// Tag 0: PropertyIdentifier (required).
	propID, consumed, ok := readInnerPropertyID(b[off:])
	if !ok {
		return 0, 0, false
	}
	off += consumed

	// Tag 1 (OPTIONAL): PropertyArrayIndex (1..3 bytes
	// primitive).
	consumed, ok = skipOptionalContextPrimitive(b[off:], isContextTag1Primitive)
	if !ok {
		return 0, 0, false
	}
	off += consumed

	// Tag 2 OPENING (0x2E): value starts.
	if off >= len(b) || b[off] != 0x2E {
		return 0, 0, false
	}
	off++

	// Walk balanced opening/closing pairs until the matching
	// tag-2 closing (0x2F).
	consumed, ok = skipUntilDepthZero(b[off:])
	if !ok {
		return 0, 0, false
	}
	off += consumed

	// Tag 3 (OPTIONAL): Priority (1..3 bytes primitive).
	consumed, ok = skipOptionalContextPrimitive(b[off:], isContextTag3Primitive)
	if !ok {
		return 0, 0, false
	}
	off += consumed

	return off, propID, true
}

// skipOptionalContextPrimitive consumes a primitive context tag
// (1..3 bytes) when match(b[0]) is true. Returns 0 when the
// tag is absent (legitimate — the field is OPTIONAL). Returns
// (0, false) on a malformed length.
func skipOptionalContextPrimitive(b []byte, match func(byte) bool) (int, bool) {
	if len(b) == 0 || !match(b[0]) {
		return 0, true
	}
	ln := int(b[0] & 0x07)
	if ln == 0 || ln > 3 || 1+ln > len(b) {
		return 0, false
	}
	return 1 + ln, true
}

// skipUntilDepthZero walks balanced BACnet opening/closing tag
// pairs, starting AT depth 1 (the caller has already consumed
// the outer opening), until the matching closing brings us
// back to depth 0. Returns the bytes consumed (including the
// terminating closing byte). Fails closed on truncation or an
// extended-length value the gate's threat model doesn't cover.
func skipUntilDepthZero(b []byte) (int, bool) {
	off := 0
	depth := 1
	for depth > 0 {
		if off >= len(b) {
			return 0, false
		}
		tag := b[off]
		off++
		consumed, ok := skipOneTagBody(b[off:], tag, &depth)
		if !ok {
			return 0, false
		}
		off += consumed
	}
	return off, true
}

// skipOneTagBody handles the L/V (length / value) field of one
// tag byte. Updates depth when L/V == 6 (opening) or 7
// (closing); reads the inline / extended length otherwise and
// returns the number of body bytes consumed.
func skipOneTagBody(rest []byte, tag byte, depth *int) (int, bool) {
	switch tag & 0x07 {
	case 0x06:
		*depth++
		return 0, true
	case 0x07:
		*depth--
		return 0, true
	case 0x05:
		// Extended length: next byte holds the count, unless
		// the count itself is ≥ 254 (further-extended). Real
		// WPM bodies never hit that path — we fail closed.
		if len(rest) < 1 {
			return 0, false
		}
		ln := int(rest[0])
		if ln >= 254 {
			return 0, false
		}
		if 1+ln > len(rest) {
			return 0, false
		}
		return 1 + ln, true
	default:
		ln := int(tag & 0x07)
		if ln > len(rest) {
			return 0, false
		}
		return ln, true
	}
}

// readInnerPropertyID reads a context-tag-0 PropertyIdentifier
// (1..3 bytes unsigned) from inside a BACnetPropertyValue.
// Valid tag bytes: 0x09 / 0x0A / 0x0B. Returns (id, bytes-
// consumed, ok).
func readInnerPropertyID(b []byte) (uint32, int, bool) {
	if len(b) < 1 {
		return 0, 0, false
	}
	tag := b[0]
	// Tag = 0, class = context, primitive: tag byte top nibble
	// must be 0000 and bit 3 must be 1 (context).
	if tag&0xF8 != 0x08 {
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

// isContextTag1Primitive reports whether b is a context-tag-1
// primitive byte (0x19 / 0x1A / 0x1B for length 1/2/3).
func isContextTag1Primitive(b byte) bool {
	if b&0xF8 != 0x18 {
		return false
	}
	ln := b & 0x07
	return ln >= 1 && ln <= 3
}

// isContextTag3Primitive reports whether b is a context-tag-3
// primitive byte (0x39 / 0x3A / 0x3B).
func isContextTag3Primitive(b byte) bool {
	if b&0xF8 != 0x38 {
		return false
	}
	ln := b & 0x07
	return ln >= 1 && ln <= 3
}
