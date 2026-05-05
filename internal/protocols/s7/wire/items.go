package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// WriteItem describes one (area, db, byte-address) tuple
// extracted from the parameter area of an S7 WriteVar
// (FuncWriteVar = 0x05) request. v1.52 chunk 1.
//
// Each WriteVar request can target multiple variables in
// one request — the parameter area carries an item list
// (count byte + N × 12-byte items in the most common
// "S7ANY" syntax). The gate uses this to refuse a
// WriteVar that targets ANY address outside the operator's
// per-(area, db, addr) allowlist.
//
// Fields:
//   - Area      — S7 area code (0x81=I, 0x82=Q, 0x83=M,
//     0x84=DB, 0x85=DI, 0x86=L, 0x87=V).
//   - DB        — DB number (0 for non-DB areas).
//   - ByteAddr  — byte offset within the area, computed
//     from the 24-bit bit-address field as
//     bit_addr >> 3. For byte/word/dword
//     access the source bit_offset is 0,
//     so ByteAddr is the start byte. For
//     bit access the gate matches on the
//     containing byte (operator-grain control
//     on bit positions is intentionally not
//     exposed — operators allowlist DBs and
//     byte ranges, not individual bits).
//   - Length    — element count from the item header,
//     scaled by transport size to give a
//     byte length. Useful for range overlap
//     checks: an item that says "16 bytes
//     starting at DB42:100" must fit within
//     an allowlist entry that covers
//     DB42:100..115.
type WriteItem struct {
	Area     uint8
	DB       uint16
	ByteAddr uint32
	Length   uint32
}

// Sentinel errors for WriteVar parsing failures. Callers
// (the offensive gate) treat any of these as "refuse the
// frame" — a malformed WriteVar request shouldn't be
// allowed through even if the operator's allowlist
// happens to cover what we managed to parse.
var (
	// ErrWriteVarShortPDU means the S7 PDU is shorter
	// than the s7HeaderMin + the parameter-area FC byte.
	ErrWriteVarShortPDU = errors.New("s7: WriteVar PDU too short")
	// ErrWriteVarBadFC means the parameter area's first
	// byte isn't 0x05. Caller should already have
	// classified, but the parser double-checks.
	ErrWriteVarBadFC = errors.New("s7: not a WriteVar request")
	// ErrWriteVarShortItem means an item header claims
	// more bytes than the parameter area provides.
	ErrWriteVarShortItem = errors.New("s7: WriteVar item truncated")
	// ErrWriteVarUnknownSyntax means an item uses a
	// syntax id we don't parse. We support only S7ANY
	// (0x10) — DB-symbolic / NCK / Drives addressing
	// would need separate parsers and aren't common in
	// production gating contexts.
	ErrWriteVarUnknownSyntax = errors.New("s7: WriteVar item uses unsupported syntax id")
)

// s7anySyntaxID is the syntax-id byte that identifies the
// classic S7ANY addressing form (DB+offset). The other
// forms (DB-symbolic, NCK, Drives ES) are vendor-specific
// + rare; v1.52 supports S7ANY only and refuses items
// that use anything else.
const s7anySyntaxID = 0x10

// itemHeaderS7ANYLen is the on-wire length of one S7ANY
// item: 1 spec + 1 length + 1 syntax + 1 transport-size
// + 2 count + 2 DB + 1 area + 3 address = 12 bytes.
const itemHeaderS7ANYLen = 12

// transportSizeBytes maps the S7 transport-size byte to
// the byte-width per element. Used to compute the item's
// total byte length from the count field. Unknown
// transport sizes default to 1 (single-byte) which gates
// conservatively — the operator's allowlist must cover
// the start address regardless of element width.
func transportSizeBytes(t uint8) uint32 {
	switch t {
	case 0x01: // BIT — packed 1 bit per element; gating uses byte granularity
		return 1
	case 0x02, 0x03: // BYTE, CHAR
		return 1
	case 0x04, 0x05: // WORD, INT
		return 2
	case 0x06, 0x07: // DWORD, DINT
		return 4
	case 0x08: // REAL
		return 4
	case 0x09: // OCTET STRING
		return 1
	default:
		return 1
	}
}

// ParseWriteVarItems extracts the WriteItem list from an
// S7 PDU's parameter area. `s7PDU` is the bytes starting
// at the protocol-id byte (0x32) — i.e. the inner PDU
// returned by the gate's innerPDU helper.
//
// Returns the extracted items + nil on success. Any
// inconsistency (short header, item truncation, unknown
// syntax) returns the appropriate sentinel + the items
// parsed up to the failure point. The gate's
// shouldForward logic treats a non-nil error as "refuse"
// so partial parses don't accidentally allow.
func ParseWriteVarItems(s7PDU []byte) ([]WriteItem, error) {
	if len(s7PDU) < s7HeaderMin+1 {
		return nil, fmt.Errorf("%w: %d bytes", ErrWriteVarShortPDU, len(s7PDU))
	}
	rosctr := s7PDU[1]
	off := s7HeaderMin
	if rosctr == ROSCTRAck || rosctr == ROSCTRAckData {
		off += 2
	}
	if off+1 >= len(s7PDU) {
		return nil, fmt.Errorf("%w: param area too short", ErrWriteVarShortPDU)
	}
	if s7PDU[off] != 0x05 {
		return nil, fmt.Errorf("%w: fc=0x%02x", ErrWriteVarBadFC, s7PDU[off])
	}
	itemCount := int(s7PDU[off+1])
	cursor := off + 2

	items := make([]WriteItem, 0, itemCount)
	for i := 0; i < itemCount; i++ {
		if cursor+itemHeaderS7ANYLen > len(s7PDU) {
			return items, fmt.Errorf("%w: item %d truncated", ErrWriteVarShortItem, i)
		}
		// Spec byte (0x12) and length (0x0A) — we don't
		// strictly validate them; some vendor stacks
		// extend the item header. We do require the
		// syntax-id byte to be S7ANY.
		syntax := s7PDU[cursor+2]
		if syntax != s7anySyntaxID {
			return items, fmt.Errorf("%w: item %d syntax=0x%02x", ErrWriteVarUnknownSyntax, i, syntax)
		}
		transport := s7PDU[cursor+3]
		count := binary.BigEndian.Uint16(s7PDU[cursor+4 : cursor+6])
		dbNum := binary.BigEndian.Uint16(s7PDU[cursor+6 : cursor+8])
		area := s7PDU[cursor+8]
		// 24-bit address: 3 bytes BE, treated as bit-addr.
		bitAddr := uint32(s7PDU[cursor+9])<<16 |
			uint32(s7PDU[cursor+10])<<8 |
			uint32(s7PDU[cursor+11])
		byteAddr := bitAddr >> 3
		lenBytes := uint32(count) * transportSizeBytes(transport)
		items = append(items, WriteItem{
			Area:     area,
			DB:       dbNum,
			ByteAddr: byteAddr,
			Length:   lenBytes,
		})
		cursor += itemHeaderS7ANYLen
	}
	return items, nil
}
