package wire

import (
	"encoding/hex"
	"testing"
)

// TestParseAPCI_RealCapture validates the IEC 60870-5-104 APCI parser against
// a real I-format frame, byte for byte from ITI ICS-pcap
// "IEC 60870/IEC104_SQ/IEC104_SQ.pcapng".
func TestParseAPCI_RealCapture(t *testing.T) {
	// 68 1d 02 00 02 00 : start, length 29, I-format control (send/recv seq 1).
	b, err := hex.DecodeString("681d02000200")
	if err != nil {
		t.Fatal(err)
	}
	a, err := ParseAPCI(b)
	if err != nil {
		t.Fatalf("ParseAPCI on a real frame: %v", err)
	}
	if a.Length != 0x1d {
		t.Errorf("Length = %d, want 29", a.Length)
	}
	if a.Control != [4]byte{0x02, 0x00, 0x02, 0x00} {
		t.Errorf("Control = %x, want 02000200", a.Control)
	}
}
