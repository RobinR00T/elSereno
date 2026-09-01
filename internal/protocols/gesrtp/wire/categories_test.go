package wire_test

import (
	"testing"

	"local/elsereno/internal/protocols/gesrtp/wire"
)

// buildMailbox crafts a 56-byte GE-SRTP client mailbox with the given
// message-type byte (offset 31) and service code at the SHORT (42) or
// EXTENDED (50) offset.
func buildMailbox(msgType, svc byte, extended bool) []byte {
	m := make([]byte, wire.MailboxLen)
	m[0] = 0x02 // pkt type = REQ
	m[31] = msgType
	if extended {
		m[50] = svc
	} else {
		m[42] = svc
	}
	return m
}

func TestClassify(t *testing.T) {
	reads := []wire.ServiceCode{
		wire.SvcShortStatus, wire.SvcGetProgName, wire.SvcReadSysMem,
		wire.SvcReadTaskMem, wire.SvcReadProgMem, wire.SvcGetTime,
		wire.SvcGetFault, wire.SvcGetInfo,
	}
	for _, c := range reads {
		if got := wire.Classify(c); got != wire.CategoryRead {
			t.Errorf("Classify(0x%02x) = %v, want Read", byte(c), got)
		}
	}
	writes := []wire.ServiceCode{
		wire.SvcWriteSysMem, wire.SvcWriteTaskMem, wire.SvcWriteProgMem,
		wire.SvcProgLogon, wire.SvcChangePriv, wire.SvcSetCPUID,
		wire.SvcSetPLCRun, wire.SvcSetPLCTime, wire.SvcClrFault,
		wire.SvcProgStore, wire.SvcProgLoad, wire.SvcToggleForce,
	}
	for _, c := range writes {
		if got := wire.Classify(c); got != wire.CategoryWrite {
			t.Errorf("Classify(0x%02x) = %v, want Write", byte(c), got)
		}
	}
	for _, c := range []wire.ServiceCode{0x01, 0x10, 0x99, 0xFF} {
		if got := wire.Classify(c); got != wire.CategoryUnknown {
			t.Errorf("Classify(0x%02x) = %v, want Unknown", byte(c), got)
		}
	}
}

// TestClassify_SafetyInvariant guards the two codes whose "read"
// classification would be dangerous: CHANGE_PRIV (0x21, the nmap-vs-
// dissector conflict) and PROG_STORE (0x3f, program exfiltration).
func TestClassify_SafetyInvariant(t *testing.T) {
	if wire.Classify(wire.SvcChangePriv) == wire.CategoryRead {
		t.Error("CHANGE_PRIV (0x21) classified as Read")
	}
	if wire.Classify(wire.SvcProgStore) == wire.CategoryRead {
		t.Error("PROG_STORE (0x3f) classified as Read")
	}
	if wire.Classify(wire.SvcSetPLCRun) == wire.CategoryRead {
		t.Error("SET_PLC_RUN (0x23) classified as Read")
	}
}

func TestExtractServiceCode(t *testing.T) {
	// SHORT request: service code at offset 42.
	if got, ok := wire.ExtractServiceCode(buildMailbox(0xC0, byte(wire.SvcWriteSysMem), false)); !ok || got != wire.SvcWriteSysMem {
		t.Errorf("SHORT extract = (0x%02x, %v), want WriteSysMem", byte(got), ok)
	}
	// EXTENDED request: service code at offset 50.
	if got, ok := wire.ExtractServiceCode(buildMailbox(0x80, byte(wire.SvcSetPLCRun), true)); !ok || got != wire.SvcSetPLCRun {
		t.Errorf("EXTENDED extract = (0x%02x, %v), want SetPLCRun", byte(got), ok)
	}
	// An ACK message type is a response, never gated.
	if _, ok := wire.ExtractServiceCode(buildMailbox(0xD4, 0x04, false)); ok {
		t.Error("ExtractServiceCode accepted a SHORT_ACK response")
	}
	// Too short to carry the message-type byte.
	if _, ok := wire.ExtractServiceCode(make([]byte, 20)); ok {
		t.Error("ExtractServiceCode accepted a 20-byte frame")
	}
}

// FuzzClassifyPipeline: ExtractServiceCode + Classify never panic on
// arbitrary input and Classify stays in range.
func FuzzClassifyPipeline(f *testing.F) {
	f.Add([]byte{})
	f.Add(buildMailbox(0xC0, byte(wire.SvcReadSysMem), false))
	f.Add(buildMailbox(0x80, byte(wire.SvcWriteSysMem), true))
	f.Fuzz(func(t *testing.T, buf []byte) {
		if code, ok := wire.ExtractServiceCode(buf); ok {
			switch wire.Classify(code) {
			case wire.CategoryRead, wire.CategoryWrite, wire.CategoryUnknown:
			default:
				t.Fatalf("Classify out of range for 0x%02x", byte(code))
			}
		}
	})
}
