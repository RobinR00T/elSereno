package wire

import "encoding/binary"

// FileObjectType is the BACnetObjectType value reserved for File
// objects (ASHRAE 135 §21). AtomicWriteFile (svc 7) ALWAYS
// targets a File object — that's what makes per-instance
// allowlisting unambiguous (the operator only declares the
// instance number; the type is implicit).
const FileObjectType uint16 = 10

// ParseAtomicWriteFile extracts the File object instance number
// from an AtomicWriteFile confirmed-request APDU. Input is the
// APDU bytes AFTER the 4-byte confirmed-request header (the
// caller has already verified service choice == 7 via
// ParseAPDUHeader).
//
// AtomicWriteFile-Request layout (ASHRAE 135 §15.8):
//
//	fileIdentifier   BACnetObjectIdentifier
//	accessSpecifier  CHOICE {
//	  streamAccess  [0] SEQUENCE { fileStartPosition INTEGER, fileData OCTET STRING },
//	  recordAccess  [1] SEQUENCE { fileStartRecord INTEGER, recordCount Unsigned, fileRecordData SEQUENCE OF OCTET STRING }
//	}
//
// Wire-level structure of the field we care about:
//
//	0xC4 PP PP PP PP    APPLICATION tag 12 (BACnetObjectIdentifier),
//	                    primitive, length 4. The 4 bytes pack
//	                    (10-bit ObjectType << 22) | (22-bit
//	                    ObjectInstance) — ObjectType MUST be
//	                    10 (File) per the spec.
//
// The gate inspects only the File instance — ObjectType is
// validated against the FileObjectType constant (any other
// type is a malformed AtomicWriteFile and fails closed). The
// access specifier (stream vs record + bytes/records to
// write) is irrelevant to the gate decision; the operator
// allowlists "writes to File#N are permitted" not "writes to
// File#N starting at offset M".
//
// Returns (instance, true) on success, (0, false) on any parse
// error or wrong ObjectType — the gate fails closed.
func ParseAtomicWriteFile(apdu []byte) (uint32, bool) {
	if len(apdu) < 5 {
		return 0, false
	}
	// Application tag 12, primitive, length 4 = 0xC4.
	// Layout: bits 7..4 = 1100 (tag 12), bit 3 = 0 (application
	// class), bits 2..0 = 100 (length 4).
	if apdu[0] != 0xC4 {
		return 0, false
	}
	raw := binary.BigEndian.Uint32(apdu[1:5])
	objType := uint16((raw >> 22) & 0x3FF)
	if objType != FileObjectType {
		// The spec requires ObjectType == 10 (File). Anything
		// else is malformed — fail closed.
		return 0, false
	}
	objInst := raw & 0x3FFFFF
	return objInst, true
}
