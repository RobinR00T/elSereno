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

func mustHexS(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
