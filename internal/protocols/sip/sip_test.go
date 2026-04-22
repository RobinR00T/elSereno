package sip_test

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"local/elsereno/internal/core"
	"local/elsereno/internal/protocols/sip"
)

// udpResponder listens on a loopback UDP socket, reads one
// packet, writes the supplied reply back to the source address,
// and returns the bound port + a stop func.
func udpResponder(t *testing.T, reply string) (int, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	lc := net.ListenConfig{}
	conn, err := lc.ListenPacket(ctx, "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 4096)
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		_ = n
		_, _ = conn.WriteTo([]byte(reply), addr)
	}()
	udpAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("LocalAddr is not *net.UDPAddr: %T", conn.LocalAddr())
	}
	return udpAddr.Port, func() {
		cancel()
		_ = conn.Close()
	}
}

// tcpResponder listens on a loopback TCP socket, accepts one
// connection, reads until CRLFCRLF, writes reply, closes.
func tcpResponder(t *testing.T, reply string) (int, func()) {
	t.Helper()
	lc := net.ListenConfig{}
	ctx, cancel := context.WithCancel(context.Background())
	ln, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 4096)
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte(reply))
	}()
	tcpAddr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("ln.Addr is not *net.TCPAddr: %T", ln.Addr())
	}
	return tcpAddr.Port, func() { cancel(); _ = ln.Close() }
}

func probeAt(t *testing.T, transport string, port int) *core.Finding {
	t.Helper()
	plug := sip.Default()
	plug.DialTimeout = 1 * time.Second
	plug.IOTimeout = 1 * time.Second
	plug.Transport = transport
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	f, err := plug.Probe(ctx, core.Target{
		Address: netip.MustParseAddr("127.0.0.1"),
		Port:    core.Port(port), //nolint:gosec // G115 — loopback test port
	})
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	return f
}

func asteriskReply() string {
	return "SIP/2.0 200 OK\r\n" +
		"Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-probe\r\n" +
		"From: <sip:elsereno@127.0.0.1>;tag=probe\r\n" +
		"To: <sip:127.0.0.1>;tag=as1234\r\n" +
		"Call-ID: probe@127.0.0.1\r\n" +
		"CSeq: 1 OPTIONS\r\n" +
		"Server: Asterisk PBX 20.1.0\r\n" +
		"Allow: INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, SUBSCRIBE\r\n" +
		"Content-Length: 0\r\n" +
		"\r\n"
}

func TestProbe_UDPAsterisk(t *testing.T) {
	port, stop := udpResponder(t, asteriskReply())
	defer stop()
	f := probeAt(t, "udp", port)
	if f.Protocol != sip.Name {
		t.Fatalf("protocol = %q", f.Protocol)
	}
	// Asterisk is in the VendorRisk=90 bucket.
	if f.Factors["protocol_risk"] != 90 {
		t.Fatalf("protocol_risk = %d, want 90 (Asterisk)", f.Factors["protocol_risk"])
	}
	if f.Factors["capability"] != 60 {
		t.Fatalf("capability = %d, want 60 (SIP confirmed)", f.Factors["capability"])
	}
}

func TestProbe_TCP3CX(t *testing.T) {
	reply := "SIP/2.0 200 OK\r\n" +
		"Via: SIP/2.0/TCP 127.0.0.1\r\n" +
		"From: <sip:elsereno@127.0.0.1>;tag=probe\r\n" +
		"To: <sip:127.0.0.1>;tag=3cx1\r\n" +
		"Call-ID: probe@127.0.0.1\r\n" +
		"CSeq: 1 OPTIONS\r\n" +
		"User-Agent: 3CX Phone System 20.0.0.123\r\n" +
		"Content-Length: 0\r\n" +
		"\r\n"
	port, stop := tcpResponder(t, reply)
	defer stop()
	f := probeAt(t, "tcp", port)
	if f.Factors["protocol_risk"] != 90 {
		t.Fatalf("protocol_risk = %d, want 90 (3CX)", f.Factors["protocol_risk"])
	}
}

func TestProbe_CiscoUCM401(t *testing.T) {
	reply := "SIP/2.0 401 Unauthorized\r\n" + //nolint:misspell // RFC 3261 §21.4 spelling
		"Via: SIP/2.0/UDP 127.0.0.1\r\n" +
		"From: <sip:elsereno@127.0.0.1>;tag=probe\r\n" +
		"To: <sip:127.0.0.1>\r\n" +
		"Call-ID: probe@127.0.0.1\r\n" +
		"Server: Cisco-CUCM11.5\r\n" +
		"WWW-Authenticate: Digest realm=\"ccm\"\r\n" +
		"Content-Length: 0\r\n" +
		"\r\n"
	port, stop := udpResponder(t, reply)
	defer stop()
	f := probeAt(t, "udp", port)
	// CUCM is VendorRisk=85; auth_state drops to 50 on 401.
	if f.Factors["protocol_risk"] != 85 {
		t.Fatalf("protocol_risk = %d, want 85 (CUCM)", f.Factors["protocol_risk"])
	}
	if f.Factors["auth_state"] != 50 {
		t.Fatalf("auth_state = %d, want 50 (401)", f.Factors["auth_state"])
	}
}

func TestProbe_NonSIPService(t *testing.T) {
	// Responder sends an HTTP 400 — the probe should still
	// return a finding but with the default (non-SIP) factors.
	port, stop := udpResponder(t, "HTTP/1.1 400 Bad Request\r\n\r\n")
	defer stop()
	f := probeAt(t, "udp", port)
	if f.Factors["capability"] != 30 {
		t.Fatalf("non-SIP capability should default to 30, got %d", f.Factors["capability"])
	}
}

func TestProbe_NoListenerErrors(t *testing.T) {
	// Nothing on a random high port → dial times out (UDP) or
	// connection refused (TCP). Either way the probe returns
	// an error, no finding.
	plug := sip.Default()
	plug.DialTimeout = 200 * time.Millisecond
	plug.IOTimeout = 200 * time.Millisecond
	plug.Transport = "udp"
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	_, err := plug.Probe(ctx, core.Target{
		Address: netip.MustParseAddr("127.0.0.1"),
		Port:    core.Port(1), // very unlikely to be a SIP responder
	})
	if err == nil {
		t.Fatal("expected error when no responder")
	}
}

func TestMetadata_Port5060(t *testing.T) {
	meta := sip.Default().Metadata()
	if meta.DefaultPort != 5060 {
		t.Fatalf("port = %d, want 5060", meta.DefaultPort)
	}
	if !strings.Contains(meta.Description, "OPTIONS") {
		t.Fatalf("description should mention OPTIONS probe, got %q", meta.Description)
	}
}

func TestIdentifyVendor_Matrix(t *testing.T) {
	cases := []struct {
		server string
		ua     string
		want   sip.Vendor
	}{
		{"Asterisk PBX 20.1.0", "", sip.VendorAsterisk},
		{"", "3CX Phone System 20", sip.VendorThreeCX},
		{"Cisco-CUCM11.5", "", sip.VendorCiscoUCM},
		{"Cisco-SIPGateway/IOS-12.4", "", sip.VendorCiscoSIPGW},
		{"Mitel SIP PBX", "", sip.VendorMitel},
		{"Avaya IP Office", "", sip.VendorAvaya},
		{"Yeastar S20 / Yeastar", "", sip.VendorYeastar},
		{"Grandstream GXW4104", "", sip.VendorGrandstream},
		{"Fanvil X6U", "", sip.VendorFanvil},
		{"Yealink SIP-T46S", "", sip.VendorYealink},
		{"kamailio (5.8.0 (x86_64/linux))", "", sip.VendorKamailio},
		{"OpenSIPS (3.4.0 (x86_64/linux))", "", sip.VendorOpenSIPS},
		{"FreeSWITCH-mod_sofia/1.10.11-release", "", sip.VendorFreeSWITCH},
		{"", "", sip.VendorUnknown},
		{"Some Random SIP Server", "", sip.VendorUnknown},
	}
	for _, c := range cases {
		if got := sip.IdentifyVendor(c.server, c.ua); got != c.want {
			t.Errorf("IdentifyVendor(%q, %q) = %q, want %q", c.server, c.ua, got, c.want)
		}
	}
}
