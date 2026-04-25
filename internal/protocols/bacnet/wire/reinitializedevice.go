package wire

// ReinitializeStateOfDevice values per ASHRAE 135 §16.4.1.1.
// Operators typically want to allow only #7 activate-changes
// (post config-update) and refuse the rest. coldstart wipes
// runtime state; warmstart restarts the BACnet stack; the
// backup / restore states bracket the device-backup workflow
// (potentially destructive if interleaved with normal traffic).
const (
	ReinitStateColdstart       uint8 = 0
	ReinitStateWarmstart       uint8 = 1
	ReinitStateStartBackup     uint8 = 2
	ReinitStateEndBackup       uint8 = 3
	ReinitStateStartRestore    uint8 = 4
	ReinitStateEndRestore      uint8 = 5
	ReinitStateAbortRestore    uint8 = 6
	ReinitStateActivateChanges uint8 = 7
)

// ParseReinitializeDevice extracts the reinitializedStateOfDevice
// enum value from a ReinitializeDevice confirmed-request APDU.
// Input is the APDU bytes AFTER the 4-byte confirmed-request
// header (the caller has already verified service choice == 20
// via ParseAPDUHeader).
//
// ReinitializeDevice-Request layout (ASHRAE 135 §16.4):
//
//	[0] reinitializedStateOfDevice ENUMERATED {
//	      coldstart        (0),
//	      warmstart        (1),
//	      startbackup      (2),
//	      endbackup        (3),
//	      startrestore     (4),
//	      endrestore       (5),
//	      abortrestore     (6),
//	      activate-changes (7)
//	    }
//	[1] password CharacterString OPTIONAL
//
// Wire-level structure of the first field (the only one the
// gate inspects):
//
//	0x09 0xNN                          [0] state, primitive, length 1
//
// The 8-value enum fits in 1 byte, so the length-1 form is the
// only one observed in the wild. The password (when present)
// follows at context tag 1; the gate ignores it.
//
// Returns (state, true) on success, (0, false) on any parse
// error — the gate fails closed.
func ParseReinitializeDevice(apdu []byte) (uint8, bool) {
	if len(apdu) < 2 {
		return 0, false
	}
	// Tag byte: context tag 0, primitive, length 1.
	if apdu[0] != 0x09 {
		return 0, false
	}
	state := apdu[1]
	// Validate against the canonical enum range. ASHRAE 135-2020
	// defines 0..7; future BACnet revisions may extend, but the
	// gate fails closed on unknown states (operator can opt in
	// explicitly if a vendor extends the enum).
	if state > ReinitStateActivateChanges {
		return 0, false
	}
	return state, true
}
