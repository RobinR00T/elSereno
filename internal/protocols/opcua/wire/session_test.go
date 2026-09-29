package wire_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"local/elsereno/internal/protocols/opcua/wire"
)

// Static prefix of a real OpenSecureChannelRequest (SecurityPolicy#None)
// body: SecureChannelId(0) + SecurityPolicyUri + null SenderCertificate +
// null ReceiverCertificateThumbprint (63 bytes). From the same captured
// None session as the response fixtures. The dynamic tail (sequence
// header, RequestHeader timestamp/handle, lifetime) is not compared.
const opnRequestStaticPrefix = "000000002f000000687474703a2f2f6f7063666f756e646174696f6e2e6f72672f55412f5365637572697479506f6c696379234e6f6e65ffffffffffffffff"

func TestEncodeOpenSecureChannelRequestNone(t *testing.T) {
	enc := wire.EncodeOpenSecureChannelRequestNone(1, 1, 3600000)

	h, err := wire.ParseHeader(enc[:wire.HeaderSize])
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	if h.Type != wire.MessageOpen {
		t.Fatalf("type = %q, want OPN", h.Type)
	}
	if int(h.Length) != len(enc) {
		t.Fatalf("header length %d != actual %d", h.Length, len(enc))
	}

	body := enc[wire.HeaderSize:]
	want := mustHexS(t, opnRequestStaticPrefix)
	if len(body) < len(want) || !bytes.Equal(body[:len(want)], want) {
		t.Fatalf("static prefix mismatch vs real OPN request:\n got %x\nwant %x", body[:min(len(body), len(want))], want)
	}
}

func TestEncodeCreateSessionRequest(t *testing.T) {
	enc := wire.EncodeCreateSessionRequest(0x195f, 1, 3, 3, "opc.tcp://plc.test:4840", "elsereno", make([]byte, 32))

	h, err := wire.ParseHeader(enc[:wire.HeaderSize])
	if err != nil || h.Type != wire.MessageMessage || int(h.Length) != len(enc) {
		t.Fatalf("header: type=%q err=%v hlen=%d actual=%d", h.Type, err, h.Length, len(enc))
	}
	body := enc[wire.HeaderSize:]
	if id, ok := wire.ServiceTypeID(body); !ok || id != wire.TypeIDCreateSessionRequest {
		t.Fatalf("TypeId = (%d,%t), want %d (CreateSessionRequest)", id, ok, wire.TypeIDCreateSessionRequest)
	}
	if !bytes.Contains(enc, []byte("opc.tcp://plc.test:4840")) {
		t.Error("endpointURL not in encoded request")
	}
	if !bytes.Contains(enc, []byte("elsereno")) {
		t.Error("sessionName not in encoded request")
	}
}

func TestEncodeActivateSessionRequestAnonymous(t *testing.T) {
	authToken := []byte{0x01, 0x00, 0x7f, 0x19} // FourByte NodeId ns=0 id=0x197f
	enc := wire.EncodeActivateSessionRequestAnonymous(0x195f, 1, 4, 4, authToken, "0")

	h, err := wire.ParseHeader(enc[:wire.HeaderSize])
	if err != nil || h.Type != wire.MessageMessage || int(h.Length) != len(enc) {
		t.Fatalf("header: type=%q err=%v hlen=%d actual=%d", h.Type, err, h.Length, len(enc))
	}
	body := enc[wire.HeaderSize:]
	if id, ok := wire.ServiceTypeID(body); !ok || id != wire.TypeIDActivateSessionRequest {
		t.Fatalf("TypeId = (%d,%t), want %d (ActivateSessionRequest)", id, ok, wire.TypeIDActivateSessionRequest)
	}
	// authToken must be echoed in the RequestHeader (right after the TypeId).
	if !bytes.Contains(body[20:28], authToken) {
		t.Errorf("authToken not echoed in RequestHeader: % x", body[20:28])
	}
	// AnonymousIdentityToken ExtensionObject TypeId: FourByte ns=0 id=321
	// = 01 00 41 01, followed by encoding 0x01.
	if !bytes.Contains(enc, []byte{0x01, 0x00, 0x41, 0x01, 0x01}) {
		t.Error("AnonymousIdentityToken (id 321) ExtensionObject not encoded")
	}
}

func TestEncodeGetEndpointsRequestTCP(t *testing.T) {
	enc := wire.EncodeGetEndpointsRequestTCP(0x195f, 1, 2, 2, "opc.tcp://plc.test:4840")
	h, err := wire.ParseHeader(enc[:wire.HeaderSize])
	if err != nil || h.Type != wire.MessageMessage || int(h.Length) != len(enc) {
		t.Fatalf("header: type=%q err=%v hlen=%d actual=%d", h.Type, err, h.Length, len(enc))
	}
	body := enc[wire.HeaderSize:]
	if id, ok := wire.ServiceTypeID(body); !ok || id != wire.TypeIDGetEndpointsRequest {
		t.Fatalf("TypeId = (%d,%t), want %d (GetEndpointsRequest)", id, ok, wire.TypeIDGetEndpointsRequest)
	}
	if !bytes.Contains(enc, []byte("opc.tcp://plc.test:4840")) {
		t.Error("endpointURL not in encoded request")
	}
}

func mustHexS(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
