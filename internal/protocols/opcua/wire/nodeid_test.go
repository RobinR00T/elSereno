package wire

import "testing"

func TestNodeIDText(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
		want string
	}{
		{"twobyte", []byte{0x00, 0x55}, "i=85"},
		{"fourbyte ns0", FourByteNodeID(42), "i=42"},
		{"fourbyte ns2", []byte{0x01, 0x02, 0x2a, 0x00}, "ns=2;i=42"},
		{"numeric ns0", []byte{0x02, 0x00, 0x00, 0x39, 0x30, 0x00, 0x00}, "i=12345"},
		{"numeric ns5", []byte{0x02, 0x05, 0x00, 0x39, 0x30, 0x00, 0x00}, "ns=5;i=12345"},
		{"string", append([]byte{0x03, 0x02, 0x00}, tStr("Temp")...), "ns=2;s=Temp"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := NodeIDText(tc.raw); got != tc.want {
				t.Fatalf("NodeIDText(% x) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestNodeIDString_Malformed(t *testing.T) {
	if got := NodeIDText([]byte{0x01, 0x00}); got != "?" { // FourByte cut short
		t.Fatalf("truncated NodeId = %q, want %q", got, "?")
	}
}
