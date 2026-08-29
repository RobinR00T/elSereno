//go:build offensive

package enip

import (
	"bytes"
	"testing"

	enipwire "local/elsereno/internal/protocols/enip/wire"
)

// mustBuild builds a CIP write/admin packet or fails the test.
func mustBuild(t *testing.T, r Request) []byte {
	t.Helper()
	pkt, err := Build(r)
	if err != nil {
		t.Fatalf("Build(%v): %v", r.Op, err)
	}
	return pkt
}

// symbolEPath addresses Symbol class 0x6B, instance 1, attribute 1
// using standard CIP logical segments (class16 / instance16 /
// attr8) that ExtractMRService parses, mirroring real client
// traffic rather than the offensive builder's internal layout.
var symbolEPath = []byte{
	0x21, 0x00, 0x6B, 0x00, // class16 = 0x6B (Symbol)
	0x25, 0x00, 0x01, 0x00, // instance16 = 1
	0x30, 0x01, // attr8 = 1
}

// mrPacket wraps a MessageRouter request (service + path) in the
// package's own SendRRData wrapper so the wire layout matches what
// the observer parses.
func mrPacket(service byte) []byte {
	// #nosec G115 -- symbolEPath is a fixed 10-byte literal, so len/2 fits a byte
	pathWords := byte(len(symbolEPath) / 2)
	mr := append([]byte{service, pathWords}, symbolEPath...)
	return wrapSendRRData(Request{}, mr)
}

// readPacket carries Get Attribute Single (0x0E, a read).
func readPacket() []byte { return mrPacket(0x0E) }

// writePacket carries Set Attribute Single (0x10, a write).
func writePacket() []byte { return mrPacket(0x10) }

// drive feeds concatenated packets through forward until EOF and
// returns the resulting exposure verdict. The handler needs no
// authorisation or allowlist: observation happens before the
// forward/refuse decision.
func drive(t *testing.T, packets ...[]byte) enipwire.ExposureVerdict {
	t.Helper()
	var in bytes.Buffer
	for _, p := range packets {
		in.Write(p)
	}
	h := &WriteGatedHandler{Target: "10.0.0.1:44818"}
	var upstream, back bytes.Buffer
	// forward returns EOF once the input is drained; that is expected.
	_ = h.forward(&in, &upstream, &back)
	return h.ExposureVerdict()
}

func TestExposureVerdict_ReadsOnlyIsClean(t *testing.T) {
	if v := drive(t, readPacket(), readPacket()); v != enipwire.VerdictClean {
		t.Fatalf("reads-only: got %v, want clean", v)
	}
}

func TestExposureVerdict_WriteIsActive(t *testing.T) {
	if v := drive(t, readPacket(), writePacket()); v != enipwire.VerdictActive {
		t.Fatalf("read+write: got %v, want active", v)
	}
}

func TestExposureVerdict_ResetIsActive(t *testing.T) {
	reset := mustBuild(t, Request{Op: OpReset})
	if v := drive(t, reset); v != enipwire.VerdictActive {
		t.Fatalf("reset: got %v, want active", v)
	}
}

func TestExposureVerdict_NoTrafficIsBlind(t *testing.T) {
	if v := drive(t); v != enipwire.VerdictBlind {
		t.Fatalf("no traffic: got %v, want blind", v)
	}
}
