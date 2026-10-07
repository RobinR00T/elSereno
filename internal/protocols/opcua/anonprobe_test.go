package opcua_test

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"local/elsereno/internal/protocols/opcua"
	"local/elsereno/internal/protocols/opcua/wire"
)

// Real captured responses (SecurityPolicy#None session,
// ITI/ICS-Security-Tools), small enough to inline.
const (
	realOPNResponse         = "4f504e46880000005f1900002f000000687474703a2f2f6f7063666f756e646174696f6e2e6f72672f55412f5365637572697479506f6c696379234e6f6e65ffffffffffffffff33000000010000000100c101edd560575c2bca01010000000000000000ffffffff000000000000005f19000001000000edd560575c2bca0180ee36000100000001"
	realActivateSessionResp = "4d534746600000005f1900000100000036000000040000000100d6011982ce575c2bca010100000000000000000000000000000020000000f37bbd064d23ec883b5e6983240f110d866b46ca4841cade8f7651cd25623f860000000000000000"
)

func le32(v uint32) []byte {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	return b[:]
}

// frameMSG prepends the UA-TCP MSG header to a body.
func frameMSG(body []byte) []byte {
	out := []byte{'M', 'S', 'G', 'F'}
	out = append(out, le32(uint32(len(body)+8))...) // #nosec G115 -- test-bounded
	return append(out, body...)
}

func buildACK() []byte {
	body := make([]byte, 20) // version + 4 buffer fields
	out := []byte{'A', 'C', 'K', 'F'}
	out = append(out, le32(uint32(len(body)+8))...) // #nosec G115 -- test-bounded
	return append(out, body...)
}

// buildCreateSessionResp is a minimal-but-valid CreateSessionResponse:
// Good serviceResult + a session id + the authentication token the
// ActivateSession must echo. The full-fixture parsing is validated in the
// wire package tests; this exercises the client's orchestration.
func buildCreateSessionResp() []byte {
	var b []byte
	b = append(b, le32(0x195f)...)        // SecureChannelId
	b = append(b, le32(1)...)             // TokenId
	b = append(b, le32(0)...)             // SequenceNumber
	b = append(b, le32(0)...)             // RequestId
	b = append(b, 0x01, 0x00, 0xd0, 0x01) // TypeId 464
	b = append(b, make([]byte, 8)...)     // Timestamp
	b = append(b, make([]byte, 4)...)     // RequestHandle
	b = append(b, make([]byte, 4)...)     // ServiceResult = Good
	b = append(b, 0x00)                   // ServiceDiagnostics
	b = append(b, make([]byte, 4)...)     // StringTable count 0
	b = append(b, 0x00, 0x00, 0x00)       // AdditionalHeader null ExtObj
	b = append(b, 0x00, 0x05)             // SessionId: TwoByte NodeId id=5
	b = append(b, 0x01, 0x00, 0x7f, 0x19) // AuthenticationToken: FourByte ns=0 id=0x197f
	return frameMSG(b)
}

// buildGetEndpointsResp wraps the real GetEndpointsResponse body (from the
// wire testdata) in a MSG so the client can decode the anonymous PolicyId.
func buildGetEndpointsResp(t *testing.T) []byte {
	t.Helper()
	realBody, err := os.ReadFile("wire/testdata/getendpoints_resp_none.bin")
	if err != nil {
		t.Fatalf("read GetEndpoints fixture: %v", err)
	}
	var b []byte
	b = append(b, le32(0x195f)...) // symmetric header prefix
	b = append(b, le32(1)...)
	b = append(b, le32(0)...)
	b = append(b, le32(0)...)
	b = append(b, realBody...)
	return frameMSG(b)
}

// serverReadMessage consumes one UA-TCP message so replies stay in sync.
func serverReadMessage(t *testing.T, r io.Reader) {
	t.Helper()
	hdr := make([]byte, wire.HeaderSize)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return
	}
	h, err := wire.ParseHeader(hdr)
	if err != nil {
		return
	}
	n := int(h.Length) - wire.HeaderSize
	if n > 0 {
		_, _ = io.ReadFull(r, make([]byte, n))
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestProbeAnonymousAccess_Confirmed(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() { _ = clientConn.Close(); _ = serverConn.Close() })

	// Fake server: replies to HELLO, OPN, GetEndpoints, CreateSession,
	// ActivateSession in order.
	responses := [][]byte{
		buildACK(),
		mustHex(t, realOPNResponse),
		buildGetEndpointsResp(t),
		buildCreateSessionResp(),
		mustHex(t, realActivateSessionResp),
	}
	go func() {
		for _, resp := range responses {
			serverReadMessage(t, serverConn)
			if _, err := serverConn.Write(resp); err != nil {
				return
			}
		}
	}()

	_ = clientConn.SetDeadline(time.Now().Add(2 * time.Second))
	res, err := opcua.ProbeAnonymousAccess(context.Background(), clientConn, "opc.tcp://plc.test:4840")
	if err != nil {
		t.Fatalf("ProbeAnonymousAccess: %v", err)
	}
	if !res.IsOPCUA {
		t.Fatal("IsOPCUA = false")
	}
	if !res.AdvertisesAnonymous || res.AnonymousPolicyID != "0" {
		t.Fatalf("anonymous advertise = %t, policyId = %q (want true, \"0\")", res.AdvertisesAnonymous, res.AnonymousPolicyID)
	}
	if !res.SessionOpened {
		t.Fatal("SessionOpened = false; expected anonymous access to be confirmed")
	}
}

// TestProbeAnonymousAccess_HelloRefusedIsOPCUA: an ERR to the Hello comes
// from a UA-TCP server (only those emit ERR), so it is OPC UA with the
// Hello refused, not "not OPC UA" (review, 2026-10-07; the opcua
// fingerprint already counted ERR as UA).
func TestProbeAnonymousAccess_HelloRefusedIsOPCUA(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() { _ = clientConn.Close(); _ = serverConn.Close() })
	// Server replies to HELLO with an ERR instead of ACK.
	go func() {
		serverReadMessage(t, serverConn)
		errMsg := []byte{'E', 'R', 'R', 'F'}
		errMsg = append(errMsg, le32(12)...)
		errMsg = append(errMsg, make([]byte, 4)...) // code
		_, _ = serverConn.Write(errMsg)
	}()
	_ = clientConn.SetDeadline(time.Now().Add(2 * time.Second))
	res, err := opcua.ProbeAnonymousAccess(context.Background(), clientConn, "opc.tcp://x:4840")
	if err != nil {
		t.Fatalf("ProbeAnonymousAccess: %v", err)
	}
	if !res.IsOPCUA || !res.HelloRefused || res.SessionOpened {
		t.Fatalf("an ERR to the Hello must yield IsOPCUA, HelloRefused, no session: %+v", res)
	}
}
