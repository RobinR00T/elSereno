package wire

// LifeSafetyOperation values per ASHRAE 135 §21
// (BACnetLifeSafetyOperation enumeration). The gate inspects
// this value to scope which fire-alarm / life-safety actions
// the operator has authorised.
//
// Operationally:
//
//   - LSOOpNone (0): no-op marker.
//   - LSOOpSilence/SilenceAudible/SilenceVisual (1/2/3): HOSTILE.
//     Silencing a fire-alarm panel can lead to deaths if the
//     silencing is performed during a real incident. Operators
//     should NEVER allow these on a production life-safety bus.
//   - LSOOpReset/ResetAlarm/ResetFault (4/5/6): operationally
//     significant. Resets clear alarm/fault state — useful after
//     manual verification, dangerous if performed on an active
//     alarm before the cause is addressed.
//   - LSOOpUnsilence/UnsilenceAudible/UnsilenceVisual (7/8/9):
//     SAFE direction. Undoes a prior silence — allows alarm
//     audible/visual indicators to resume. Typical recovery
//     after an attacker silenced a panel.
const (
	LSOOpNone             uint8 = 0
	LSOOpSilence          uint8 = 1
	LSOOpSilenceAudible   uint8 = 2
	LSOOpSilenceVisual    uint8 = 3
	LSOOpReset            uint8 = 4
	LSOOpResetAlarm       uint8 = 5
	LSOOpResetFault       uint8 = 6
	LSOOpUnsilence        uint8 = 7
	LSOOpUnsilenceAudible uint8 = 8
	LSOOpUnsilenceVisual  uint8 = 9
)

// ParseLifeSafetyOperation extracts the request enum value from
// a LifeSafetyOperation confirmed-request APDU. Input is the
// APDU bytes AFTER the 4-byte confirmed-request header (the
// caller has already verified service choice == 27 via
// ParseAPDUHeader).
//
// LifeSafetyOperation-Request layout (ASHRAE 135 §16.1A):
//
//	[0] requestingProcessIdentifier  Unsigned
//	[1] requestingSource             CharacterString
//	[2] request                      BACnetLifeSafetyOperation
//	[3] objectIdentifier             BACnetObjectIdentifier OPTIONAL
//
// All four fields are context-tagged primitives. The first two
// are skipped (the gate doesn't care about the operator's
// process ID or display name); the third is read; the fourth
// is ignored at gate level (per-object scoping for LSO is a
// v1.16+ extension if anyone asks).
//
// Wire-level structure of the field we care about:
//
//	0x29 NN              [2] request, primitive, length 1, enum value NN
//
// Returns (op, true) on success, (0, false) on any parse error
// or unknown enum value — the gate fails closed.
func ParseLifeSafetyOperation(apdu []byte) (uint8, bool) {
	off := 0
	// [0] requestingProcessIdentifier — Unsigned, length 1..4.
	next, ok := skipContextPrimitiveField(apdu, off, 0)
	if !ok {
		return 0, false
	}
	off = next
	// [1] requestingSource — CharacterString, length 1..4 inline
	// or extended (length-byte form).
	next, ok = skipContextPrimitiveField(apdu, off, 1)
	if !ok {
		return 0, false
	}
	off = next
	// [2] request — ENUMERATED, length 1.
	if off+1 >= len(apdu) {
		return 0, false
	}
	if apdu[off] != 0x29 { // context 2, primitive, length 1
		return 0, false
	}
	op := apdu[off+1]
	// Validate against the canonical 0..9 range. ASHRAE 135-2020
	// stops at 9; future revisions may extend, but the gate
	// fails closed on unknown ops (operator can opt in
	// explicitly when a vendor extends the enum).
	if op > LSOOpUnsilenceVisual {
		return 0, false
	}
	return op, true
}

// skipContextPrimitiveField skips a primitive context-tagged
// field starting at off. Validates the tag number matches
// expectedTagNum (0..14). Handles inline lengths 0..4 and the
// extended-length form (low-bits == 5, length follows in the
// next byte).
//
// Constructed forms (low-bits == 6/7 — opening/closing) are
// rejected — those are SEQUENCE wrappers, not primitives.
//
// Returns (newOffset, true) on success; (off, false) on any
// failure (truncated, wrong tag class/number, constructed
// form where primitive expected).
func skipContextPrimitiveField(b []byte, off int, expectedTagNum uint8) (int, bool) {
	if off >= len(b) {
		return off, false
	}
	tag := b[off]
	// Tag-number nibble must match.
	if (tag >> 4) != expectedTagNum {
		return off, false
	}
	// Class bit (bit 3) must be 1 (context).
	if tag&0x08 == 0 {
		return off, false
	}
	lnBits := tag & 0x07
	if lnBits == 6 || lnBits == 7 {
		// Constructed open/close — primitive expected.
		return off, false
	}
	off++
	var ln int
	if lnBits == 5 {
		// Extended-length form: next byte is actual length 5..253.
		if off >= len(b) {
			return off, false
		}
		ln = int(b[off])
		off++
	} else {
		ln = int(lnBits)
	}
	if off+ln > len(b) {
		return off, false
	}
	return off + ln, true
}
