package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// EPathTarget describes the (class, instance, attribute)
// triple parsed from a CIP MessageRouter request EPATH.
// v1.53 chunk 1.
//
// CIP MR requests target an object on the device by walking
// a logical-segment path:
//
//	8-bit form    21 CC                 (class CC)
//	16-bit form   21 00 CC CC           (class CCCC)
//	32-bit form   22 00 CC CC CC CC     (class CCCCCCCC)
//
// Then the same triple of forms for instance (24/25/26)
// and attribute (30/31/32). Logical segments are
// well-defined in CIP Vol 1 Chapter 1.
//
// We parse the most common 8/16-bit forms; 32-bit forms
// (which only Rockwell Logix uses for some symbols) parse
// successfully but the gate evaluates them at full
// uint32 precision.
//
// `Has*` flags signal which segments were present —
// many MR requests omit attribute (target the whole
// instance), and a few omit instance (target the class).
type EPathTarget struct {
	Class       uint32
	Instance    uint32
	Attribute   uint32
	HasClass    bool
	HasInstance bool
	HasAttr     bool
}

// CIP logical-segment format byte values. Top 3 bits =
// segment type (0b001 = LogicalSegment), next 3 bits =
// logical type (Class/Instance/Member/Attribute), low 2
// bits = format (8/16/32-bit).
const (
	logicalClass8     byte = 0x20
	logicalClass16    byte = 0x21
	logicalClass32    byte = 0x22
	logicalInstance8  byte = 0x24
	logicalInstance16 byte = 0x25
	logicalInstance32 byte = 0x26
	logicalAttr8      byte = 0x30
	logicalAttr16     byte = 0x31
	logicalAttr32     byte = 0x32
)

// Sentinels for EPATH parsing failures.
var (
	// ErrEPathTooShort is returned when an EPATH segment
	// claims more bytes than the path provides.
	ErrEPathTooShort = errors.New("enip: EPATH segment truncated")
	// ErrEPathUnknownSegment is returned when the path
	// contains a segment type we don't classify
	// (port-segments, symbolic, network-segments).
	// Gate refuses on this — partial parse can't
	// safely allow.
	ErrEPathUnknownSegment = errors.New("enip: EPATH unknown segment type")
)

// readSegmentValue decodes the value of one logical-
// segment (8-bit / 16-bit / 32-bit). The size is
// determined by the low 2 bits of the segment byte.
// Returns (value, byte-stride). A bounds-check failure
// returns ErrEPathTooShort. The bounds check is
// centralised here so the dispatcher stays small and
// gosec sees one safe slice access per width.
func readSegmentValue(path []byte, cursor int, seg byte) (uint32, int, error) {
	switch seg & 0x03 {
	case 0x00: // 8-bit form: type byte + value byte
		if cursor+2 > len(path) {
			return 0, 0, fmt.Errorf("%w: 8-bit at %d", ErrEPathTooShort, cursor)
		}
		// #nosec G602 -- bounds check above guarantees cursor+1 < len(path).
		return uint32(path[cursor+1]), 2, nil
	case 0x01: // 16-bit form: type + pad + 2 LE bytes
		if cursor+4 > len(path) {
			return 0, 0, fmt.Errorf("%w: 16-bit at %d", ErrEPathTooShort, cursor)
		}
		// #nosec G602 -- bounds check above.
		return uint32(binary.LittleEndian.Uint16(path[cursor+2 : cursor+4])), 4, nil
	case 0x02: // 32-bit form: type + pad + 4 LE bytes
		if cursor+6 > len(path) {
			return 0, 0, fmt.Errorf("%w: 32-bit at %d", ErrEPathTooShort, cursor)
		}
		// #nosec G602 -- bounds check above.
		return binary.LittleEndian.Uint32(path[cursor+2 : cursor+6]), 6, nil
	}
	return 0, 0, fmt.Errorf("%w: format=0x%02x", ErrEPathUnknownSegment, seg)
}

// ParseMRPath extracts the (class, instance, attribute)
// triple from a CIP MR request EPATH. `path` is the
// bytes after the 1-byte path-size word count (caller
// already extracted via pathSize × 2 bytes).
//
// Returns the parsed target. Unknown segments cause an
// error so the gate refuses; multi-segment paths with
// padding (8-bit forms followed by a pad byte) are
// handled per CIP spec.
func ParseMRPath(path []byte) (EPathTarget, error) {
	var t EPathTarget
	cursor := 0
	for cursor < len(path) {
		seg := path[cursor]
		// Mask the low 2 bits (size format) to get the
		// segment+logical-type byte.
		segType := seg &^ 0x03
		var assign func(v uint32)
		switch segType {
		case logicalClass8:
			assign = func(v uint32) { t.Class = v; t.HasClass = true }
		case logicalInstance8:
			assign = func(v uint32) { t.Instance = v; t.HasInstance = true }
		case logicalAttr8:
			assign = func(v uint32) { t.Attribute = v; t.HasAttr = true }
		default:
			return t, fmt.Errorf("%w: 0x%02x at %d", ErrEPathUnknownSegment, seg, cursor)
		}
		val, stride, err := readSegmentValue(path, cursor, seg)
		if err != nil {
			return t, err
		}
		assign(val)
		cursor += stride
	}
	return t, nil
}

// ExtractMRTarget is a higher-level helper that finds the
// MR request inside a SendRRData or SendUnitData body
// and parses its EPATH.
//
// CIP encapsulation body layout (for SendRRData):
//
//	InterfaceHandle (4) + Timeout (2) + CPF
//	CPF: ItemCount (2) + Items
//	  Item: TypeID (2) + Length (2) + Data
//
// We look for the Unconnected Data Item (TypeID 0x00B2)
// and parse its data as MR Request:
//
//	Service (1) + PathSize (1, words) + Path (PathSize×2)
//	+ Data
//
// Returns (target, true) when the MR can be parsed.
// Returns (_, false) for non-MR encapsulation commands
// (ListIdentity etc.) or malformed bodies — the gate
// treats false as "no per-attr constraint applies",
// falling back to the command-level allowlist.
func ExtractMRTarget(body []byte) (EPathTarget, bool) {
	// SendRRData prelude: 4 + 2 = 6 bytes.
	if len(body) < 6 {
		return EPathTarget{}, false
	}
	cpf := body[6:]
	if len(cpf) < 2 {
		return EPathTarget{}, false
	}
	itemCount := binary.LittleEndian.Uint16(cpf[0:2])
	cursor := 2
	for i := uint16(0); i < itemCount; i++ {
		if cursor+4 > len(cpf) {
			return EPathTarget{}, false
		}
		typeID := binary.LittleEndian.Uint16(cpf[cursor : cursor+2])
		itemLen := binary.LittleEndian.Uint16(cpf[cursor+2 : cursor+4])
		cursor += 4
		if cursor+int(itemLen) > len(cpf) {
			return EPathTarget{}, false
		}
		if typeID == 0x00B2 || typeID == 0x00A2 {
			// Unconnected (B2) or Connected (A2) data item.
			// MR request: service + pathSize + path + data.
			itemData := cpf[cursor : cursor+int(itemLen)]
			if len(itemData) < 2 {
				return EPathTarget{}, false
			}
			pathSizeWords := int(itemData[1])
			pathBytes := pathSizeWords * 2
			if 2+pathBytes > len(itemData) {
				return EPathTarget{}, false
			}
			path := itemData[2 : 2+pathBytes]
			t, err := ParseMRPath(path)
			if err != nil {
				return EPathTarget{}, false
			}
			return t, true
		}
		cursor += int(itemLen)
	}
	return EPathTarget{}, false
}
