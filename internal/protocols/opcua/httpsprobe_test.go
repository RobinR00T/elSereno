package opcua_test

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"local/elsereno/internal/protocols/opcua"
	"local/elsereno/internal/protocols/opcua/wire"
)

// encodeTestResponse hand-builds a GetEndpointsResponse with one
// SignAndEncrypt endpoint and one None endpoint, mirroring the wire
// package's round-trip test but from the plugin's external test.
func encodeTestResponse() []byte {
	var b []byte
	put32 := func(v uint32) { var t [4]byte; binary.LittleEndian.PutUint32(t[:], v); b = append(b, t[:]...) }
	str := func(s string) { put32(uint32(len(s))); b = append(b, s...) } // #nosec G115 -- test string length fits uint32.
	nullStr := func() { put32(0xFFFFFFFF) }
	nullArr := func() { put32(0xFFFFFFFF) }
	// message TypeId: FourByte NodeId of GetEndpointsResponse.
	b = append(b, byte(wire.NodeIDFourByte), 0x00)
	var t [2]byte
	binary.LittleEndian.PutUint16(t[:], wire.TypeIDGetEndpointsResponse)
	b = append(b, t[:]...)
	// ResponseHeader.
	put32(0)
	put32(0)                        // timestamp
	put32(1)                        // requestHandle
	put32(0)                        // serviceResult
	b = append(b, 0x00)             // serviceDiagnostics mask
	nullArr()                       // stringTable
	b = append(b, 0x00, 0x00, 0x00) // additionalHeader null ExtensionObject
	// endpoints array: 2.
	put32(2)
	writeEndpoint := func(url string, mode uint32, policy string, level byte) {
		str(url)
		// ApplicationDescription.
		str("urn:host:UA")
		str("urn:host:product")
		b = append(b, 0x02) // LocalizedText: text present
		str("HostServer")
		put32(0)  // applicationType
		nullStr() // gatewayServerUri
		nullStr() // discoveryProfileUri
		nullArr() // discoveryUrls
		// serverCertificate ByteString.
		put32(2)
		b = append(b, 0x01, 0x02)
		put32(mode)
		str(policy)
		nullArr() // userIdentityTokens
		str("http://opcfoundation.org/UA-Profile/Transport/https-uabinary")
		b = append(b, level)
	}
	writeEndpoint("opc.https://host:443/UA", wire.SecurityModeSignAndEncrypt,
		"http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256", 3)
	writeEndpoint("opc.https://host:443/None", wire.SecurityModeNone,
		"http://opcfoundation.org/UA/SecurityPolicy#None", 0)
	return b
}

func TestProbeHTTPS_DecodesEndpoints(t *testing.T) {
	var gotReqBody []byte
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "want POST", http.StatusMethodNotAllowed)
			return
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/octet-stream" {
			t.Errorf("Content-Type = %q", ct)
		}
		gotReqBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(encodeTestResponse())
	}))
	defer srv.Close()

	eps, err := opcua.ProbeHTTPS(context.Background(), srv.URL, "opc.https://host:443/UA", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(eps) != 2 {
		t.Fatalf("endpoints = %d, want 2", len(eps))
	}
	if eps[0].SecurityMode != wire.SecurityModeSignAndEncrypt || eps[1].SecurityMode != wire.SecurityModeNone {
		t.Errorf("security modes = %d, %d", eps[0].SecurityMode, eps[1].SecurityMode)
	}
	if wire.SecurityModeName(eps[1].SecurityMode) != "None" {
		t.Errorf("SecurityModeName(None) = %q", wire.SecurityModeName(eps[1].SecurityMode))
	}
	// The server must have received a valid GetEndpointsRequest.
	id, ok := requestTypeID(gotReqBody)
	if !ok || id != wire.TypeIDGetEndpointsRequest {
		t.Errorf("server received TypeId=%d ok=%v, want %d", id, ok, wire.TypeIDGetEndpointsRequest)
	}
}

func TestProbeHTTPS_NonUAResponse(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<html>not opc ua</html>"))
	}))
	defer srv.Close()
	_, err := opcua.ProbeHTTPS(context.Background(), srv.URL, "opc.https://host/UA", 5*time.Second)
	if !errors.Is(err, opcua.ErrHTTPSNotUA) {
		t.Fatalf("err = %v, want ErrHTTPSNotUA", err)
	}
}

func TestProbeHTTPS_HTTPError(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()
	_, err := opcua.ProbeHTTPS(context.Background(), srv.URL, "opc.https://host/UA", 5*time.Second)
	if !errors.Is(err, opcua.ErrHTTPSNotUA) {
		t.Fatalf("err = %v, want ErrHTTPSNotUA", err)
	}
}

// TestProbe_HTTPSFallback drives the whole plugin: the UA-TCP HEL to a
// TLS endpoint fails to parse, so Probe falls back to the HTTPS
// GetEndpoints binding and emits a ua-https finding — with the
// exposure/auth bump because one advertised endpoint is SecurityMode
// None.
func TestProbe_HTTPSFallback(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(encodeTestResponse()) // 2 endpoints, one None
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}

	f := probeAt(port)
	if f == nil {
		t.Fatal("Probe returned no finding for a UA HTTPS server")
	}
	if f.Factors["exposure"] != 90 || f.Factors["auth_state"] != 90 {
		t.Errorf("ua-https finding factors = exposure %d auth_state %d, want 90/90 (None endpoint)",
			f.Factors["exposure"], f.Factors["auth_state"])
	}
}

func requestTypeID(body []byte) (uint16, bool) {
	if len(body) < 4 || body[0] != byte(wire.NodeIDFourByte) || body[1] != 0x00 {
		return 0, false
	}
	return uint16(body[2]) | uint16(body[3])<<8, true
}
