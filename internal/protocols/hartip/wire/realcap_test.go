package wire_test

import (
	"encoding/hex"
	"testing"

	"local/elsereno/internal/protocols/hartip/wire"
)

// TestParseHeader_RealCapture validates the HART-IP header parser against
// real session-initiate frames, byte for byte from CISA cisagov/icsnpp-hart-ip
// testing/traces/hart-ip.pcap.
func TestParseHeader_RealCapture(t *testing.T) {
	cases := []struct {
		name      string
		frame     string
		version   uint8
		msgType   uint8
		msgID     uint8
		status    uint8
		sequence  uint16
		byteCount uint16
	}{
		{"session_init_request", "010000000002000d", 1, 0, 0, 0, 2, 13},
		{"session_init_response", "010100000002000d", 1, 1, 0, 0, 2, 13},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, err := hex.DecodeString(tc.frame)
			if err != nil {
				t.Fatal(err)
			}
			h, err := wire.ParseHeader(b)
			if err != nil {
				t.Fatalf("ParseHeader on a real frame: %v", err)
			}
			if h.Version != tc.version || h.MsgType != tc.msgType || h.MsgID != tc.msgID ||
				h.Status != tc.status || h.Sequence != tc.sequence || h.ByteCount != tc.byteCount {
				t.Errorf("header = %+v, want ver=%d type=%d id=%d status=%d seq=%d bytecount=%d",
					h, tc.version, tc.msgType, tc.msgID, tc.status, tc.sequence, tc.byteCount)
			}
		})
	}
}

// TestBuildSessionInitiate_RealCapture validates the probe request, not
// only the parser: with the capture's sequence number, the session
// initiate we send is byte for byte the real client's (CISA
// icsnpp-hart-ip hart-ip.pcap, identical over UDP and TCP).
func TestBuildSessionInitiate_RealCapture(t *testing.T) {
	const captured = "010000000002000d0100007530"
	if got := hex.EncodeToString(wire.BuildSessionInitiate(2)); got != captured {
		t.Fatalf("BuildSessionInitiate(2) = %s, want the captured client request %s", got, captured)
	}
}
