package exposure

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestProtocolForPort(t *testing.T) {
	cases := []struct {
		port     int
		protocol string
		secure   string
	}{
		{502, "modbus", ""},
		{102, "s7comm / iso-tsap", ""},
		{80, "http", "https"},
		{23, "telnet", "ssh"},
		{44818, "ethernet-ip", ""},
		{9999, "", ""}, // unknown
	}
	for _, c := range cases {
		p, s := ProtocolForPort(c.port)
		if p != c.protocol || s != c.secure {
			t.Errorf("ProtocolForPort(%d) = (%q,%q), want (%q,%q)", c.port, p, s, c.protocol, c.secure)
		}
	}
}

func TestProbeCleartext_TLSService(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	defer ts.Close()
	addr := ts.Listener.Addr().String()

	res, err := ProbeCleartext(context.Background(), addr, 3*time.Second)
	if err != nil {
		t.Fatalf("ProbeCleartext: %v", err)
	}
	if !res.Reachable {
		t.Fatal("Reachable = false for a live TLS server")
	}
	if !res.TLS {
		t.Errorf("TLS = false for an HTTPS server; res = %+v", res)
	}
	if res.Cleartext {
		t.Error("Cleartext = true for a TLS server")
	}
	if res.TLSVersion == "" {
		t.Error("TLSVersion empty for a TLS service")
	}
}

func TestProbeCleartext_PlaintextService(t *testing.T) {
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	// Accept and close: a service that speaks TCP but not TLS.
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	res, err := ProbeCleartext(context.Background(), ln.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatalf("ProbeCleartext: %v", err)
	}
	if !res.Reachable {
		t.Fatal("Reachable = false for a live plaintext server")
	}
	if res.TLS {
		t.Errorf("TLS = true for a plaintext server; res = %+v", res)
	}
	if !res.Cleartext {
		t.Error("Cleartext = false for a reachable non-TLS service")
	}
}

// selfSigned returns a throwaway self-signed leaf certificate with the
// given expiry, for standing up a test TLS listener.
func selfSigned(t *testing.T, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     notAfter,
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// startTLSListener stands up a TLS server with cfg that handshakes and
// closes each connection, enough for ProbeCleartext's main + version-pinned
// probes. Returns its address.
func startTLSListener(t *testing.T, cfg *tls.Config) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(cn net.Conn) {
				if tc, ok := cn.(*tls.Conn); ok {
					_ = tc.HandshakeContext(context.Background())
				}
				_ = cn.Close()
			}(c)
		}
	}()
	return ln.Addr().String()
}

// A modern TLS service (min 1.2, unexpired cert) must have a clean posture:
// no deprecated version accepted, cert not expired, WeakTLS false.
func TestProbeCleartext_ModernTLS_CleanPosture(t *testing.T) {
	cfg := &tls.Config{
		Certificates: []tls.Certificate{selfSigned(t, time.Now().Add(365*24*time.Hour))},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
	}
	addr := startTLSListener(t, cfg)

	res, err := ProbeCleartext(context.Background(), addr, 3*time.Second)
	if err != nil {
		t.Fatalf("ProbeCleartext: %v", err)
	}
	if !res.TLS {
		t.Fatalf("TLS = false for a modern TLS server; res = %+v", res)
	}
	if len(res.DeprecatedTLS) != 0 {
		t.Errorf("DeprecatedTLS = %v, want none (server is min TLS 1.2)", res.DeprecatedTLS)
	}
	if res.CertExpired {
		t.Error("CertExpired = true for an unexpired cert")
	}
	if res.WeakTLS {
		t.Errorf("WeakTLS = true for a clean modern TLS service; res = %+v", res)
	}
}

// A service that still accepts TLS 1.0 / 1.1 must be flagged WeakTLS with
// both deprecated versions confirmed.
func TestProbeCleartext_WeakTLS_DeprecatedVersions(t *testing.T) {
	cfg := &tls.Config{ // #nosec G402 -- test fixture: an intentionally weak TLS 1.0/1.1 server, exists precisely to verify the weak-TLS detector
		Certificates: []tls.Certificate{selfSigned(t, time.Now().Add(365*24*time.Hour))},
		MinVersion:   tls.VersionTLS10,
		MaxVersion:   tls.VersionTLS11,
	}
	addr := startTLSListener(t, cfg)

	res, err := ProbeCleartext(context.Background(), addr, 3*time.Second)
	if err != nil {
		t.Fatalf("ProbeCleartext: %v", err)
	}
	if !res.TLS {
		t.Fatalf("TLS = false for a TLS 1.1 server; res = %+v", res)
	}
	if !res.WeakTLS {
		t.Errorf("WeakTLS = false for a service accepting deprecated TLS; res = %+v", res)
	}
	got := map[string]bool{}
	for _, v := range res.DeprecatedTLS {
		got[v] = true
	}
	if !got["TLS 1.0"] || !got["TLS 1.1"] {
		t.Errorf("DeprecatedTLS = %v, want both TLS 1.0 and TLS 1.1", res.DeprecatedTLS)
	}
}

// An expired certificate on an otherwise-modern service is flagged WeakTLS
// via CertExpired, with no deprecated version accepted.
func TestProbeCleartext_ExpiredCert(t *testing.T) {
	cfg := &tls.Config{
		Certificates: []tls.Certificate{selfSigned(t, time.Now().Add(-1*time.Hour))},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
	}
	addr := startTLSListener(t, cfg)

	res, err := ProbeCleartext(context.Background(), addr, 3*time.Second)
	if err != nil {
		t.Fatalf("ProbeCleartext: %v", err)
	}
	if !res.TLS {
		t.Fatalf("TLS = false; res = %+v", res)
	}
	if !res.CertExpired {
		t.Errorf("CertExpired = false for an expired cert (NotAfter %s)", res.CertNotAfter)
	}
	if len(res.DeprecatedTLS) != 0 {
		t.Errorf("DeprecatedTLS = %v, want none (server is min TLS 1.2)", res.DeprecatedTLS)
	}
	if !res.WeakTLS {
		t.Error("WeakTLS = false despite an expired certificate")
	}
}

func TestProbeCleartext_Unreachable(t *testing.T) {
	// Port 1 on loopback refuses fast.
	res, err := ProbeCleartext(context.Background(), "127.0.0.1:1", 2*time.Second)
	if err != nil {
		t.Fatalf("ProbeCleartext: %v", err)
	}
	if res.Reachable || res.Cleartext || res.TLS {
		t.Fatalf("an unreachable target must be all-false: %+v", res)
	}
}
