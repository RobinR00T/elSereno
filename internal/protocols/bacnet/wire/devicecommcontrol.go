package wire

// DeviceCommControl enableDisable values per ASHRAE 135 §16.1.
//
//   - DCCStateEnable: re-enable communication on a device that
//     was previously disabled (the SAFE direction — undoes a
//     prior silence).
//   - DCCStateDisable: silence the device's BACnet communication
//     for the requested duration (or indefinitely). DESTRUCTIVE —
//     blocks all monitoring + alarms during incidents.
//   - DCCStateDisableInitiation: device may still respond to
//     requests but will NOT initiate any (no I-Am, no
//     UnconfirmedCOVNotification, no event broadcasts). Subtler
//     attack vector; still hostile.
const (
	DCCStateEnable            uint8 = 0
	DCCStateDisable           uint8 = 1
	DCCStateDisableInitiation uint8 = 2
)

// ParseDeviceCommControl extracts the enableDisable enum value
// from a DeviceCommunicationControl confirmed-request APDU.
// Input is the APDU bytes AFTER the 4-byte confirmed-request
// header (the caller has already verified service choice == 17
// via ParseAPDUHeader).
//
// DeviceCommunicationControl-Request layout (ASHRAE 135 §16.1):
//
//	[0] timeDuration   Unsigned         OPTIONAL
//	[1] enableDisable  ENUMERATED { enable(0), disable(1),
//	                                disableInitiation(2) }
//	[2] password       CharacterString  OPTIONAL
//
// Wire-level structure:
//
//	0x09..0x0C  TT[..]      [0] timeDuration, primitive, length 1..4
//	                        (OPTIONAL — skipped when present)
//	0x19  NN                [1] enableDisable, primitive, length 1
//	0x29..  ?? ..           [2] password (OPTIONAL — ignored)
//
// The gate inspects only the enableDisable enum. The password
// (when present) is left to the device's own auth layer.
//
// Returns (state, true) on success, (0, false) on any parse
// error or unknown enum value — the gate fails closed.
func ParseDeviceCommControl(apdu []byte) (uint8, bool) {
	if len(apdu) < 2 {
		return 0, false
	}
	off := 0
	// Optional [0] timeDuration: tag bytes 0x09..0x0C (context 0,
	// primitive, length 1..4). Skip past it when present.
	if isContextTag0Primitive(apdu[off]) {
		ln := int(apdu[off] & 0x07)
		// Reject the extended-length form (length=5) and
		// constructed forms (0x0E/0x0F) — neither is valid for
		// a primitive Unsigned timeDuration.
		if ln < 1 || ln > 4 {
			return 0, false
		}
		off += 1 + ln
		if off >= len(apdu) {
			return 0, false
		}
	}
	// [1] enableDisable: tag byte 0x19 (context 1, primitive,
	// length 1). The enum is 0..2 today.
	if apdu[off] != 0x19 {
		return 0, false
	}
	off++
	if off >= len(apdu) {
		return 0, false
	}
	state := apdu[off]
	if state > DCCStateDisableInitiation {
		// Unknown enum value — fail closed. Future BACnet
		// revisions may extend; operators must opt in
		// explicitly.
		return 0, false
	}
	return state, true
}

// isContextTag0Primitive reports whether b is one of the four
// primitive context-tag-0 length-1..4 markers used by BACnet
// for the optional [0] field. Excludes the constructed forms
// (0x0E/0x0F) and the extended-length form (0x0D).
func isContextTag0Primitive(b byte) bool {
	return b >= 0x09 && b <= 0x0C
}
