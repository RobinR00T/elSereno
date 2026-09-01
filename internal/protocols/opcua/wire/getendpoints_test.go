package wire_test

import (
	"encoding/binary"
	"errors"
	"testing"

	"local/elsereno/internal/protocols/opcua/wire"
)

// ---- small UA Binary encoder for building test responses ----------

type enc struct{ b []byte }

func (e *enc) u8(v byte) { e.b = append(e.b, v) }
func (e *enc) u32(v uint32) {
	var t [4]byte
	binary.LittleEndian.PutUint32(t[:], v)
	e.b = append(e.b, t[:]...)
}
func (e *enc) i32(v int32) { e.u32(uint32(v)) } // #nosec G115 -- test encoder; Int32/uint32 reinterpret.
func (e *enc) str(s string) {
	if s == "" {
		e.i32(-1) // null
		return
	}
	e.u32(uint32(len(s))) // #nosec G115 -- test string length fits uint32.
	e.b = append(e.b, s...)
}
func (e *enc) nullArray() { e.i32(-1) }
func (e *enc) byteStr(b []byte) {
	if b == nil {
		e.i32(-1)
		return
	}
	e.u32(uint32(len(b))) // #nosec G115 -- test bytestring length fits uint32.
	e.b = append(e.b, b...)
}
func (e *enc) fourByteNodeID(id uint16) {
	e.u8(byte(wire.NodeIDFourByte))
	e.u8(0x00)
	var t [2]byte
	binary.LittleEndian.PutUint16(t[:], id)
	e.b = append(e.b, t[:]...)
}
func (e *enc) nullNodeID()          { e.u8(0x00); e.u8(0x00) }
func (e *enc) nullExtensionObject() { e.nullNodeID(); e.u8(0x00) }
func (e *enc) responseHeader() {
	e.u32(0)
	e.u32(0)                // timestamp (8 bytes)
	e.u32(1)                // requestHandle
	e.u32(0)                // serviceResult
	e.u8(0x00)              // serviceDiagnostics: DiagnosticInfo, empty mask
	e.nullArray()           // stringTable
	e.nullExtensionObject() // additionalHeader
}

// localizedText with locale+text present.
func (e *enc) localizedText(text string) {
	e.u8(0x02) // text-present bit only
	e.str(text)
}

func (e *enc) applicationDescription(appURI, prodURI, name string) {
	e.str(appURI)
	e.str(prodURI)
	e.localizedText(name)
	e.u32(0)      // applicationType = Server
	e.str("")     // gatewayServerUri (null)
	e.str("")     // discoveryProfileUri (null)
	e.nullArray() // discoveryUrls
}

func (e *enc) endpoint(url string, mode uint32, policy string, level byte) {
	e.str(url)
	e.applicationDescription("urn:test:UA:Server", "urn:test:product", "TestServer")
	e.byteStr([]byte{0xDE, 0xAD}) // serverCertificate
	e.u32(mode)
	e.str(policy)
	e.nullArray() // userIdentityTokens
	e.str("http://opcfoundation.org/UA-Profile/Transport/https-uabinary")
	e.u8(level)
}

func buildResponse(endpoints int) []byte {
	e := &enc{}
	e.fourByteNodeID(wire.TypeIDGetEndpointsResponse)
	e.responseHeader()
	e.i32(int32(endpoints)) // #nosec G115 -- test endpoint count is tiny.
	if endpoints >= 1 {
		e.endpoint("opc.https://plc.local:443/UA", wire.SecurityModeSignAndEncrypt,
			"http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256", 3)
	}
	if endpoints >= 2 {
		e.endpoint("opc.https://plc.local:443/UA-None", wire.SecurityModeNone,
			"http://opcfoundation.org/UA/SecurityPolicy#None", 0)
	}
	return e.b
}

// ---- tests --------------------------------------------------------

func TestEncodeGetEndpointsRequest_RoundTrip(t *testing.T) {
	body := wire.EncodeGetEndpointsRequest("opc.https://host:443/UA")
	// The body must open with the GetEndpointsRequest DefaultBinary
	// NodeId in FourByte form (enc 0x01, ns 0, id LE).
	if len(body) < 4 || body[0] != byte(wire.NodeIDFourByte) || body[1] != 0x00 {
		t.Fatalf("request does not open with FourByte NodeId: % x", body[:min(4, len(body))])
	}
	id := uint16(body[2]) | uint16(body[3])<<8
	if id != wire.TypeIDGetEndpointsRequest {
		t.Fatalf("request TypeId = %d, want %d", id, wire.TypeIDGetEndpointsRequest)
	}
	// The endpointUrl we passed must appear verbatim in the body.
	if !bytesContains(body, []byte("opc.https://host:443/UA")) {
		t.Fatalf("endpointUrl not encoded in request body")
	}
}

func TestDecodeGetEndpointsResponse_TwoEndpoints(t *testing.T) {
	eps, err := wire.DecodeGetEndpointsResponse(buildResponse(2))
	if err != nil {
		t.Fatal(err)
	}
	if len(eps) != 2 {
		t.Fatalf("endpoints = %d, want 2", len(eps))
	}
	e0 := eps[0]
	if e0.EndpointURL != "opc.https://plc.local:443/UA" {
		t.Errorf("EndpointURL = %q", e0.EndpointURL)
	}
	if e0.SecurityMode != wire.SecurityModeSignAndEncrypt {
		t.Errorf("SecurityMode = %d, want SignAndEncrypt", e0.SecurityMode)
	}
	if e0.SecurityPolicyURI != "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256" {
		t.Errorf("SecurityPolicyURI = %q", e0.SecurityPolicyURI)
	}
	if e0.SecurityLevel != 3 {
		t.Errorf("SecurityLevel = %d, want 3", e0.SecurityLevel)
	}
	if e0.ApplicationURI != "urn:test:UA:Server" {
		t.Errorf("ApplicationURI = %q", e0.ApplicationURI)
	}
	if e0.ApplicationName != "TestServer" {
		t.Errorf("ApplicationName = %q", e0.ApplicationName)
	}
	// The None endpoint (security posture flag) must decode too.
	if eps[1].SecurityMode != wire.SecurityModeNone {
		t.Errorf("ep1 SecurityMode = %d, want None", eps[1].SecurityMode)
	}
}

func TestDecodeGetEndpointsResponse_Empty(t *testing.T) {
	eps, err := wire.DecodeGetEndpointsResponse(buildResponse(0))
	if err != nil {
		t.Fatal(err)
	}
	if len(eps) != 0 {
		t.Fatalf("endpoints = %d, want 0", len(eps))
	}
}

func TestDecodeGetEndpointsResponse_WrongType(t *testing.T) {
	e := &enc{}
	e.fourByteNodeID(wire.TypeIDGetEndpointsRequest) // wrong: a request TypeId
	_, err := wire.DecodeGetEndpointsResponse(e.b)
	if !errors.Is(err, wire.ErrWrongResponseType) {
		t.Fatalf("err = %v, want ErrWrongResponseType", err)
	}
}

func TestDecodeGetEndpointsResponse_Truncated(t *testing.T) {
	full := buildResponse(2)
	_, err := wire.DecodeGetEndpointsResponse(full[:len(full)-10])
	if !errors.Is(err, wire.ErrShortResponse) {
		t.Fatalf("err = %v, want ErrShortResponse", err)
	}
}

func TestDecodeGetEndpointsResponse_HostileCount(t *testing.T) {
	e := &enc{}
	e.fourByteNodeID(wire.TypeIDGetEndpointsResponse)
	e.responseHeader()
	e.u32(0x7FFFFFFF) // absurd endpoint count
	_, err := wire.DecodeGetEndpointsResponse(e.b)
	if !errors.Is(err, wire.ErrTooManyEndpoints) {
		t.Fatalf("err = %v, want ErrTooManyEndpoints", err)
	}
}

func FuzzDecodeGetEndpointsResponse(f *testing.F) {
	f.Add(buildResponse(2))
	f.Add([]byte{0x01, 0x00, 0xAF, 0x01})
	f.Fuzz(func(_ *testing.T, buf []byte) {
		// Must never panic; error or endpoints, nothing else.
		_, _ = wire.DecodeGetEndpointsResponse(buf)
	})
}

// bytesContains is a tiny helper (avoids importing bytes just for one call).
func bytesContains(haystack, needle []byte) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if string(haystack[i:i+len(needle)]) == string(needle) {
			return true
		}
	}
	return false
}
