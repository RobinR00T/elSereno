package wire_test

import (
	"encoding/hex"
	"testing"

	"local/elsereno/internal/protocols/gesrtp/wire"
)

// TestClassifyResponse_RealInitReply validates the GE-SRTP connection-init
// classifier against the real device reply byte for byte.
//
// The bytes are the 56-byte mailbox a real GE PLC returns to the all-zero
// CONNECTION INIT frame. Two independent sources agree on them:
//
//   - Collin Matthews' GE_SRTP implementation, tested against real GE 90/30
//     and 90/70 CPUs: "first send 56 bytes of all 0s to the PLC before real
//     message. It will respond with 01 00 ..." (lib/GE_SRTP_Messages.py).
//   - The Shodan "general-electric-srtp" product signature for port 18245,
//     recorded in automayt/ICS-pcap GE-SRTP/Notes.txt: a 56-byte reply whose
//     byte 0 is 0x01 and byte 8 is 0x0f.
//
// This is the bug that PITF-067 records: the parser previously modelled the
// OPERATION message (request 0x02 / response 0x03) and sent 0x02 as the
// "connection init", expecting 0x03 back, so against a real PLC it rejected
// the genuine 0x01 init reply. The fix sends the all-zero init frame and
// accepts the 0x01 reply.
func TestClassifyResponse_RealInitReply(t *testing.T) {
	reply, err := hex.DecodeString("01000000000000000f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	if len(reply) != wire.MailboxLen {
		t.Fatalf("real init reply length = %d, want %d", len(reply), wire.MailboxLen)
	}
	if reply[0] != wire.TypeInitResponse {
		t.Fatalf("real init reply byte 0 = 0x%02x, want 0x01", reply[0])
	}
	if err := wire.ClassifyResponse(reply); err != nil {
		t.Fatalf("ClassifyResponse rejected a real GE-SRTP init reply: %v", err)
	}
	if !wire.IsMailboxResponse(reply) {
		t.Fatal("IsMailboxResponse = false for a real init reply")
	}
	// And the init frame we SEND must be all zeros (what the PLC expects
	// before it will answer), not a 0x02 operation request.
	init := wire.BuildConnectionInit()
	if len(init) != wire.MailboxLen {
		t.Fatalf("init frame length = %d, want %d", len(init), wire.MailboxLen)
	}
	for i, b := range init {
		if b != 0x00 {
			t.Fatalf("init frame byte %d = 0x%02x, want 0x00 (all-zero init)", i, b)
		}
	}
}
