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
	// Symbol / HasSymbol carry the ANSI extended symbol segment
	// (0x91 + tag name) that Rockwell Logix uses to address tags by
	// name. This is the dominant form for Read Tag / Write Tag, so
	// the detection path must recognise it or it goes blind to the
	// most common Logix traffic. The per-attribute gate stays scoped
	// to the numeric (class, instance, attribute) triple and ignores
	// symbolic targets, so admitting this here does not widen it.
	Symbol    string
	HasSymbol bool
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
	// symbolicSegmentANSI is the ANSI extended symbol segment
	// (CIP Vol 1): 0x91, one length byte (character count), the name
	// bytes, then a pad byte when the count is odd (word alignment).
	symbolicSegmentANSI byte = 0x91
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
		if seg == symbolicSegmentANSI {
			next, err := parseSymbolSegment(path, cursor, &t)
			if err != nil {
				return t, err
			}
			cursor = next
			continue
		}
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

// parseSymbolSegment decodes an ANSI extended symbol segment
// (0x91 <len> <name bytes> [pad]) at cursor, records the tag name in
// t, and returns the cursor position just after the segment (past the
// odd-length pad byte). This is how Rockwell Logix addresses tags by
// name, so the detection path must accept it.
func parseSymbolSegment(path []byte, cursor int, t *EPathTarget) (int, error) {
	if cursor+2 > len(path) {
		return 0, fmt.Errorf("%w: symbol length at %d", ErrEPathTooShort, cursor)
	}
	nameLen := int(path[cursor+1])
	start := cursor + 2
	end := start + nameLen
	if end > len(path) {
		return 0, fmt.Errorf("%w: symbol name at %d", ErrEPathTooShort, cursor)
	}
	t.Symbol = string(path[start:end])
	t.HasSymbol = true
	next := end
	if nameLen%2 != 0 {
		next++ // pad byte for word alignment
	}
	return next, nil
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
	_, t, ok := ExtractMRService(body)
	return t, ok
}

// ExtractMRService is ExtractMRTarget plus the MR request's
// service byte (the first byte of the MessageRouter request,
// before the path size). It is the input the CIP service
// classifier (cipservice.go) needs to label a frame for the
// detection / exposure-scoring path.
//
// Returns (service, target, true) when the MR can be parsed;
// (_, _, false) for non-MR encapsulation commands or malformed
// bodies. ExtractMRTarget delegates here so both share one
// parser and cannot drift.
func ExtractMRService(body []byte) (byte, EPathTarget, bool) {
	// SendRRData prelude: 4 + 2 = 6 bytes.
	if len(body) < 6 {
		return 0, EPathTarget{}, false
	}
	cpf := body[6:]
	if len(cpf) < 2 {
		return 0, EPathTarget{}, false
	}
	itemCount := binary.LittleEndian.Uint16(cpf[0:2])
	cursor := 2
	for i := uint16(0); i < itemCount; i++ {
		if cursor+4 > len(cpf) {
			return 0, EPathTarget{}, false
		}
		typeID := binary.LittleEndian.Uint16(cpf[cursor : cursor+2])
		itemLen := binary.LittleEndian.Uint16(cpf[cursor+2 : cursor+4])
		cursor += 4
		if cursor+int(itemLen) > len(cpf) {
			return 0, EPathTarget{}, false
		}
		if typeID == 0x00B2 || typeID == 0x00B1 {
			// Unconnected (0x00B2) or Connected (0x00B1) data item.
			itemData := cpf[cursor : cursor+int(itemLen)]
			// A Connected Data Item (0x00B1) prefixes a 2-byte
			// connection sequence count before the MR request; skip it
			// so the service/path parse aligns with what the device
			// actually executes. Unconnected (0x00B2) has no prefix.
			if typeID == 0x00B1 {
				if len(itemData) < 2 {
					return 0, EPathTarget{}, false
				}
				itemData = itemData[2:]
			}
			// MR request: service + pathSize + path + data.
			if len(itemData) < 2 {
				return 0, EPathTarget{}, false
			}
			service := itemData[0]
			pathSizeWords := int(itemData[1])
			pathBytes := pathSizeWords * 2
			if 2+pathBytes > len(itemData) {
				return 0, EPathTarget{}, false
			}
			path := itemData[2 : 2+pathBytes]
			t, err := ParseMRPath(path)
			if err != nil {
				return 0, EPathTarget{}, false
			}
			return service, t, true
		}
		cursor += int(itemLen)
	}
	return 0, EPathTarget{}, false
}
