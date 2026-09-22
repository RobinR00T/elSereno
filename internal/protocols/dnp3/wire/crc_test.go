package wire

import (
	"bytes"
	"testing"
)

// TestCRC16_CatalogueCheck pins the CRC against the published check
// value for CRC-16/DNP: CRC16("123456789") == 0xEA82.
func TestCRC16_CatalogueCheck(t *testing.T) {
	t.Parallel()
	if got := CRC16([]byte("123456789")); got != 0xEA82 {
		t.Fatalf("CRC16(\"123456789\") = 0x%04X, want 0xEA82", got)
	}
}

// TestBlockCRCs_RoundTrip proves AppendBlockCRCs / StripBlockCRCs are
// inverses across block boundaries (empty, sub-block, exactly 16,
// multi-block).
func TestBlockCRCs_RoundTrip(t *testing.T) {
	t.Parallel()
	for _, n := range []int{0, 1, 5, 16, 17, 32, 33, 100} {
		ud := make([]byte, n)
		for i := range ud {
			ud[i] = byte(i * 7)
		}
		wire := AppendBlockCRCs(ud)
		if len(wire) != n+blockCRCBytes(n) {
			t.Fatalf("n=%d: wire len %d, want %d", n, len(wire), n+blockCRCBytes(n))
		}
		got, ok := StripBlockCRCs(wire, n)
		if !ok {
			t.Fatalf("n=%d: StripBlockCRCs ok=false", n)
		}
		if !bytes.Equal(got, ud) {
			t.Fatalf("n=%d: round-trip mismatch", n)
		}
	}
}

// TestStripBlockCRCs_BadCRCFailsClosed proves a corrupted block CRC is
// rejected (the gate must not inspect a malformed frame).
func TestStripBlockCRCs_BadCRCFailsClosed(t *testing.T) {
	t.Parallel()
	ud := []byte{0xC0, 0xC1, 0x01, 0x3C, 0x01, 0x06}
	wire := AppendBlockCRCs(ud)
	wire[len(wire)-1] ^= 0xFF // corrupt the CRC high byte
	if _, ok := StripBlockCRCs(wire, len(ud)); ok {
		t.Fatal("StripBlockCRCs accepted a corrupted CRC; must fail closed")
	}
}

// TestBodyLen matches the on-wire body size to the Length field.
func TestBodyLen(t *testing.T) {
	t.Parallel()
	// Length 5 = no user data.
	if got := BodyLen(5); got != 0 {
		t.Fatalf("BodyLen(5) = %d, want 0", got)
	}
	// Length 5+6 = 11: 6 user-data octets in one block + 2 CRC.
	if got := BodyLen(11); got != 8 {
		t.Fatalf("BodyLen(11) = %d, want 8", got)
	}
	// Length 5+17 = 22: 17 octets over two blocks + 4 CRC.
	if got := BodyLen(22); got != 21 {
		t.Fatalf("BodyLen(22) = %d, want 21", got)
	}
}
