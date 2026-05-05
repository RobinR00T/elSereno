package wire

import (
	"errors"
	"testing"
)

// buildJobWriteVar constructs a minimal Job PDU (ROSCTR=0x01)
// with FC=0x05 WriteVar and the given items. Bytes-only;
// no encoder dependency.
func buildJobWriteVar(items [][]byte) []byte {
	header := []byte{
		0x32,       // protocol id
		0x01,       // ROSCTR Job
		0x00, 0x00, // redundancy
		0x00, 0x00, // pdu ref
		0x00, 0x00, // param len (filled)
		0x00, 0x00, // data len
	}
	param := []byte{0x05, byte(len(items))} // #nosec G115 -- test fixture
	for _, it := range items {
		param = append(param, it...)
	}
	header[6] = byte(len(param) >> 8)   // #nosec G115 -- test fixture
	header[7] = byte(len(param) & 0xFF) // #nosec G115 -- test fixture
	return append(header, param...)
}

// itemS7ANY builds a 12-byte S7ANY item header.
func itemS7ANY(transport uint8, count uint16, db uint16, area uint8, byteAddr uint32) []byte {
	bitAddr := byteAddr << 3
	return []byte{
		0x12, 0x0A, 0x10,
		transport,
		byte(count >> 8), byte(count & 0xFF),
		byte(db >> 8), byte(db & 0xFF),
		area,
		// #nosec G115 -- 24-bit address truncation by mask is intentional.
		byte(bitAddr >> 16), byte(bitAddr >> 8), byte(bitAddr & 0xFF),
	}
}

func TestParseWriteVarItems_Single(t *testing.T) {
	pdu := buildJobWriteVar([][]byte{
		itemS7ANY(0x02, 4, 42, 0x84, 100), // DB42, BYTE×4 starting at byte 100
	})
	items, err := ParseWriteVarItems(pdu)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("items = %d, want 1", len(items))
	}
	got := items[0]
	if got.Area != 0x84 || got.DB != 42 || got.ByteAddr != 100 || got.Length != 4 {
		t.Errorf("got %+v", got)
	}
}

func TestParseWriteVarItems_Multi(t *testing.T) {
	pdu := buildJobWriteVar([][]byte{
		itemS7ANY(0x04, 2, 10, 0x84, 0),  // DB10, WORD×2 = 4 bytes at 0
		itemS7ANY(0x02, 8, 0, 0x83, 200), // M area, BYTE×8 at 200
		itemS7ANY(0x06, 1, 50, 0x84, 16), // DB50, DWORD×1 = 4 at 16
	})
	items, err := ParseWriteVarItems(pdu)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if len(items) != 3 {
		t.Fatalf("items = %d, want 3", len(items))
	}
	if items[0].Length != 4 || items[1].Length != 8 || items[2].Length != 4 {
		t.Errorf("lengths = [%d, %d, %d]", items[0].Length, items[1].Length, items[2].Length)
	}
	if items[1].Area != 0x83 || items[1].ByteAddr != 200 {
		t.Errorf("item[1] = %+v", items[1])
	}
}

func TestParseWriteVarItems_NotWriteVar(t *testing.T) {
	pdu := buildJobWriteVar([][]byte{itemS7ANY(0x02, 1, 1, 0x84, 0)})
	pdu[10] = 0x04 // change FC to ReadVar
	_, err := ParseWriteVarItems(pdu)
	if !errors.Is(err, ErrWriteVarBadFC) {
		t.Errorf("err = %v, want ErrWriteVarBadFC", err)
	}
}

func TestParseWriteVarItems_TruncatedItem(t *testing.T) {
	pdu := buildJobWriteVar([][]byte{itemS7ANY(0x02, 1, 1, 0x84, 0)})
	// Lop off the last 4 bytes of the item.
	pdu = pdu[:len(pdu)-4]
	// Re-write param-len (now too small but we want the parser to detect on item-level).
	plen := len(pdu) - 10
	pdu[6] = byte(plen >> 8)
	pdu[7] = byte(plen & 0xFF)
	_, err := ParseWriteVarItems(pdu)
	if !errors.Is(err, ErrWriteVarShortItem) {
		t.Errorf("err = %v, want ErrWriteVarShortItem", err)
	}
}

func TestParseWriteVarItems_UnsupportedSyntax(t *testing.T) {
	pdu := buildJobWriteVar([][]byte{itemS7ANY(0x02, 1, 1, 0x84, 0)})
	// 1 (header s7HeaderMin) + 2 (FC + count) = first item starts at offset 12.
	// Syntax id is at item[2] = pdu[14].
	pdu[14] = 0x11 // not S7ANY
	_, err := ParseWriteVarItems(pdu)
	if !errors.Is(err, ErrWriteVarUnknownSyntax) {
		t.Errorf("err = %v, want ErrWriteVarUnknownSyntax", err)
	}
}

func TestParseWriteVarItems_PDUTooShort(t *testing.T) {
	pdu := []byte{0x32, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00}
	_, err := ParseWriteVarItems(pdu)
	if !errors.Is(err, ErrWriteVarShortPDU) {
		t.Errorf("err = %v, want ErrWriteVarShortPDU", err)
	}
}

func TestTransportSizeBytes(t *testing.T) {
	cases := []struct {
		t    uint8
		want uint32
	}{
		{0x01, 1}, // BIT
		{0x02, 1}, // BYTE
		{0x03, 1}, // CHAR
		{0x04, 2}, // WORD
		{0x05, 2}, // INT
		{0x06, 4}, // DWORD
		{0x07, 4}, // DINT
		{0x08, 4}, // REAL
		{0x09, 1}, // OCTET STRING
		{0xFF, 1}, // unknown → conservative default
	}
	for _, c := range cases {
		if got := transportSizeBytes(c.t); got != c.want {
			t.Errorf("transportSizeBytes(0x%02x) = %d, want %d", c.t, got, c.want)
		}
	}
}
