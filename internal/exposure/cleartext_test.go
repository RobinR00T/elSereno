package exposure

import (
	"context"
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
