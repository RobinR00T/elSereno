package opcuahttps_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"local/elsereno/internal/core"
	"local/elsereno/internal/protocols/opcuahttps"
)

// mustParseAddr converts a host string (IP literal expected
// from httptest) to netip.Addr. Fails the test on parse error.
func mustParseAddr(t *testing.T, host string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(host)
	if err != nil {
		t.Fatalf("parse addr %q: %v", host, err)
	}
	return a
}

// genSelfSignedTLSConfig produces a self-signed TLS config for
// httptest.NewUnstartedServer. Mirrors what SCADA gateways
// typically ship.
func genSelfSignedTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	tpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "opcua-https-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("x509: %v", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: priv}},
		MinVersion:   tls.VersionTLS12,
	}
}

// startTestServer wires an httptest TLS server with a custom
// response handler. Returns the host + port for Probe.
func startTestServer(t *testing.T, handler http.HandlerFunc) (string, core.Port) {
	t.Helper()
	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = genSelfSignedTLSConfig(t)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("url parse: %v", err)
	}
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatalf("splithost: %v", err)
	}
	p, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("port: %v", err)
	}
	return host, mustPort(t, p)
}

// mustPort narrows int → uint16/core.Port with a bounds
// check so the test fixture matches the integer-overflow
// guard the linter expects on production code.
func mustPort(t *testing.T, p int) core.Port {
	t.Helper()
	if p < 0 || p > 65535 {
		t.Fatalf("port out of range: %d", p)
	}
	return core.Port(p) // #nosec G115 — bounded above.
}

// TestProbe_UABinaryContentType: server replies with the
// OPC UA binary content-type → strong finding.
func TestProbe_UABinaryContentType(t *testing.T) {
	host, port := startTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/opcua+uabinary")
		w.Header().Set("Server", "Unified Automation UA HTTPS 1.7.4")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte{0x00})
	})
	target := core.Target{
		Address: mustParseAddr(t, host),
		Port:    port,
	}
	f, err := opcuahttps.Default().Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("probe err: %v", err)
	}
	if f == nil {
		t.Fatal("nil finding; expected strong UA hit")
	}
	if f.Protocol != "opcuahttps" {
		t.Errorf("protocol = %q", f.Protocol)
	}
	if f.Factors["capability"] != 75 {
		t.Errorf("capability = %d, want 75 (strong UA binding)", f.Factors["capability"])
	}
}

// TestProbe_UAServerHeaderOnly: server emits 404 with a UA
// server header → weak finding (capability=50 default).
func TestProbe_UAServerHeaderOnly(t *testing.T) {
	host, port := startTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "Prosys OPC UA SDK 4.0")
		w.WriteHeader(http.StatusNotFound)
	})
	target := core.Target{
		Address: mustParseAddr(t, host),
		Port:    port,
	}
	f, err := opcuahttps.Default().Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("probe err: %v", err)
	}
	if f == nil {
		t.Fatal("nil finding; expected weak UA hit")
	}
	if f.Factors["capability"] != 50 {
		t.Errorf("capability = %d, want 50 (weak hint)", f.Factors["capability"])
	}
}

// TestProbe_PlainHTTPS: a vanilla nginx replies normally with
// no UA hints → Probe returns (nil, nil). Saves operator noise.
func TestProbe_PlainHTTPS(t *testing.T) {
	host, port := startTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "nginx/1.25.3")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("<html>nginx default</html>"))
	})
	target := core.Target{
		Address: mustParseAddr(t, host),
		Port:    port,
	}
	f, err := opcuahttps.Default().Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("probe err: %v", err)
	}
	if f != nil {
		t.Errorf("expected nil finding for plain HTTPS; got %+v", f)
	}
}

// TestProbe_TLSHandshakeFailure: target is not even speaking
// TLS → error propagated.
func TestProbe_TLSHandshakeFailure(t *testing.T) {
	// Bind a plain TCP listener (no TLS) on a random port.
	// noctx wants Listen via a ListenConfig — fine, that lets
	// the test deadline propagate via ctx.
	lc := &net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, accErr := ln.Accept()
		if accErr != nil {
			return
		}
		_ = c.Close()
	}()
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	p, _ := strconv.Atoi(portStr)
	target := core.Target{
		Address: mustParseAddr(t, host),
		Port:    mustPort(t, p),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err = opcuahttps.Default().Probe(ctx, target)
	if err == nil {
		t.Errorf("expected TLS handshake error; got nil")
	}
	if !strings.Contains(err.Error(), "tls") {
		t.Errorf("err = %v, want TLS-related", err)
	}
}

// TestMetadata_Sane: plugin metadata announces port 4843 +
// "default" build.
func TestMetadata_Sane(t *testing.T) {
	m := opcuahttps.Default().Metadata()
	if m.Name != "opcuahttps" {
		t.Errorf("Name = %q", m.Name)
	}
	if m.DefaultPort != 4843 {
		t.Errorf("DefaultPort = %d, want 4843", m.DefaultPort)
	}
	if m.Build != "default" {
		t.Errorf("Build = %q, want default", m.Build)
	}
}

// TestProxyHandler_DenyAll: handler refuses traffic.
func TestProxyHandler_DenyAll(t *testing.T) {
	h := opcuahttps.Default().ProxyHandler()
	if h == nil {
		t.Fatal("nil handler")
	}
	err := h.Handle(context.Background(), nil, nil)
	if err == nil {
		t.Errorf("Handle returned nil; want deny error")
	}
}
