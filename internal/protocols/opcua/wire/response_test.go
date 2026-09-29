package wire_test

import (
	"encoding/hex"
	"testing"

	"local/elsereno/internal/protocols/opcua/wire"
)

// Real captured OPC UA responses (SecurityPolicy#None session), from the
// public ITI/ICS-Security-Tools OPC UA sample capture
// (opc-ua-ap-method). Full UA-TCP messages including the 8-byte header;
// the body passed to the parsers is msg[8:].
const (
	// ActivateSessionResponse (TypeId 470), serviceResult = Good.
	activateSessionResp470 = "4d534746600000005f1900000100000036000000040000000100d6011982ce575c2bca010100000000000000000000000000000020000000f37bbd064d23ec883b5e6983240f110d866b46ca4841cade8f7651cd25623f860000000000000000"
	// CreateSessionResponse (TypeId 464) ResponseHeader prefix.
	createSessionResp464Hdr = "4d534746961f00005f1900000100000035000000030000000100d0018783af575c2bca0101000000000000000000000000000000020a009193050001"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestResponseServiceResult_RealActivateSession(t *testing.T) {
	msg := mustHex(t, activateSessionResp470)
	body := msg[8:] // strip UA-TCP header

	if id, ok := wire.ServiceTypeID(body); !ok || id != 470 {
		t.Fatalf("TypeId = (%d,%t), want 470 (ActivateSessionResponse)", id, ok)
	}
	status, ok := wire.ResponseServiceResult(body)
	if !ok {
		t.Fatal("ResponseServiceResult: not ok on a real ActivateSessionResponse")
	}
	if status != wire.StatusGood {
		t.Fatalf("serviceResult = 0x%08x, want Good (session activated) on the captured response", status)
	}
}

func TestResponseServiceResult_RealCreateSessionHeader(t *testing.T) {
	msg := mustHex(t, createSessionResp464Hdr)
	body := msg[8:]
	if id, ok := wire.ServiceTypeID(body); !ok || id != 464 {
		t.Fatalf("TypeId = (%d,%t), want 464 (CreateSessionResponse)", id, ok)
	}
	status, ok := wire.ResponseServiceResult(body)
	if !ok || status != wire.StatusGood {
		t.Fatalf("serviceResult = (0x%08x,%t), want Good", status, ok)
	}
}

func TestResponseServiceResult_ShortFailsClosed(t *testing.T) {
	if _, ok := wire.ResponseServiceResult([]byte{0x01, 0x02}); ok {
		t.Error("short body must return ok=false")
	}
	if _, ok := wire.ResponseServiceResult(nil); ok {
		t.Error("nil body must return ok=false")
	}
}
