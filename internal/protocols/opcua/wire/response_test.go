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
	// CreateSessionResponse (TypeId 464), first 80 bytes: ResponseHeader
	// + SessionId + AuthenticationToken.
	createSessionResp464Hdr = "4d534746961f00005f1900000100000035000000030000000100d0018783af575c2bca0101000000000000000000000000000000020a009193050001007f1900000000004ced4020000000c1ad931075"
	// OpenSecureChannelResponse (SecurityPolicy#None), full message.
	openSecureChannelResp = "4f504e46880000005f1900002f000000687474703a2f2f6f7063666f756e646174696f6e2e6f72672f55412f5365637572697479506f6c696379234e6f6e65ffffffffffffffff33000000010000000100c101edd560575c2bca01010000000000000000ffffffff000000000000005f19000001000000edd560575c2bca0180ee36000100000001"
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

func TestParseOpenSecureChannelResponse_Real(t *testing.T) {
	msg := mustHex(t, openSecureChannelResp)
	body := msg[8:] // strip UA-TCP header
	chID, tokID, ok := wire.ParseOpenSecureChannelResponse(body)
	if !ok {
		t.Fatal("ParseOpenSecureChannelResponse: not ok on a real OPN response")
	}
	if chID != 0x195f {
		t.Errorf("ChannelId = 0x%04x, want 0x195f", chID)
	}
	if tokID != 1 {
		t.Errorf("TokenId = %d, want 1", tokID)
	}
}

func TestParseOpenSecureChannelResponse_ShortFailsClosed(t *testing.T) {
	if _, _, ok := wire.ParseOpenSecureChannelResponse([]byte{0x5f, 0x19}); ok {
		t.Error("truncated OPN response must return ok=false")
	}
}

func TestParseCreateSessionAuthToken_Real(t *testing.T) {
	msg := mustHex(t, createSessionResp464Hdr)
	body := msg[8:]
	tok, ok := wire.ParseCreateSessionAuthToken(body)
	if !ok {
		t.Fatal("ParseCreateSessionAuthToken: not ok on a real CreateSessionResponse")
	}
	// AuthenticationToken is a FourByte NodeId ns=0 id=0x197f: 01 00 7f 19.
	if got := hex.EncodeToString(tok); got != "01007f19" {
		t.Fatalf("authToken = %s, want 01007f19", got)
	}
}

func TestParseCreateSessionAuthToken_ShortFailsClosed(t *testing.T) {
	if _, ok := wire.ParseCreateSessionAuthToken([]byte{0x00, 0x01}); ok {
		t.Error("truncated CreateSessionResponse must return ok=false")
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
