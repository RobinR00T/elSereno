package wire_test

import (
	"testing"

	"local/elsereno/internal/protocols/mbustcp/wire"
)

// FuzzParseRSPUD asserts that ParseRSPUD never panics on
// arbitrary input and that, on success, the manufacturer code
// is exactly 3 ASCII characters or a hex fallback.
func FuzzParseRSPUD(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x68, 0x00, 0x00, 0x68, 0x00, 0x00, 0x00, 0x00, 0x16})
	// 21-byte successful frame with KAM manufacturer.
	full := []byte{
		0x68, 0x0F, 0x0F, 0x68,
		0x08, 0x01, 0x72,
		0x78, 0x56, 0x34, 0x12, // ID 0x12345678
		0x2D, 0x2C, // KAM
		0x12,                   // version
		0x07,                   // medium = water
		0x00, 0x00, 0x00, 0x00, // access + status + signature
	}
	var cs byte
	for _, b := range full[4:] {
		cs += b
	}
	full = append(full, cs, 0x16)
	f.Add(full)
	f.Fuzz(func(t *testing.T, buf []byte) {
		mi, err := wire.ParseRSPUD(buf)
		if err != nil {
			return
		}
		if len(mi.Manufacturer) == 0 {
			t.Fatalf("Manufacturer empty on success path")
		}
		// Successful manufacturer is either 3-letter ASCII or
		// a "0x????" hex fallback.
		if len(mi.Manufacturer) != 3 && len(mi.Manufacturer) != 6 {
			t.Fatalf("Manufacturer unexpected length %d: %q", len(mi.Manufacturer), mi.Manufacturer)
		}
	})
}

// FuzzBuildREQUD2Stable asserts the request frame is always
// 5 bytes regardless of address.
func FuzzBuildREQUD2Stable(f *testing.F) {
	f.Add(byte(0x00))
	f.Add(byte(0xFE))
	f.Fuzz(func(t *testing.T, addr byte) {
		got := wire.BuildREQUD2(addr)
		if len(got) != 5 {
			t.Fatalf("frame length: got %d want 5", len(got))
		}
		if got[2] != addr {
			t.Fatalf("addr: got 0x%02x want 0x%02x", got[2], addr)
		}
		if got[3] != byte(0x5B)+addr {
			t.Fatalf("checksum: got 0x%02x want 0x%02x", got[3], byte(0x5B)+addr)
		}
	})
}
