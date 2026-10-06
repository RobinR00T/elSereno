package atg

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"local/elsereno/internal/core"
)

func TestMetadata(t *testing.T) {
	t.Parallel()
	m := Default().Metadata()
	if m.Name != Name {
		t.Fatalf("Name: got %q want %q", m.Name, Name)
	}
	if m.DefaultPort != 10001 {
		t.Fatalf("DefaultPort: got %d want 10001", m.DefaultPort)
	}
	if !strings.Contains(strings.ToLower(m.Description), "veeder") {
		t.Fatalf("Description should mention Veeder-Root: %q", m.Description)
	}
}

func TestBuildFindingFactors(t *testing.T) {
	t.Parallel()
	target := core.Target{Address: netip.MustParseAddr("203.0.113.9"), Port: 10001}
	yes := buildFinding(target, "ATG I20100 response", true)
	no := buildFinding(target, "no ATG response", false)

	if yes.Factors["capability"] <= no.Factors["capability"] {
		t.Fatalf("capability should jump on an ATG reply: yes=%d no=%d",
			yes.Factors["capability"], no.Factors["capability"])
	}
	if no.Factors["auth_state"] != 95 {
		t.Fatalf("ATG has no auth: auth_state got %d want 95", no.Factors["auth_state"])
	}
	if yes.Factors["cve_exposure"] != 6 {
		t.Fatalf("cve_exposure: got %d want 6", yes.Factors["cve_exposure"])
	}
	if yes.Protocol != Name {
		t.Fatalf("Protocol: got %q want %q", yes.Protocol, Name)
	}
	if yes.ID == no.ID {
		t.Fatal("distinct notes must give distinct ids")
	}
}

func TestIsATGReadCommand(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   []byte
		want bool
	}{
		{[]byte("\x01I20100\r"), true},  // SOH + Info command
		{[]byte("\x01i10200\r"), true},  // lowercase i
		{[]byte("I20100\r"), true},      // no SOH, still an I command
		{[]byte("\x01S11234\r"), false}, // S = set, a write command
		{[]byte("\x01V\r"), false},      // V = setpoint, a write command
		{[]byte("\x01"), false},         // SOH only, shorter than minimum
		{[]byte(""), false},             // empty
	}
	for _, c := range cases {
		if got := isATGReadCommand(c.in); got != c.want {
			t.Errorf("isATGReadCommand(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// The write-ban proxy forwards I-family (read) commands upstream and
// refuses everything else with the Veeder-Root 9999FF1B data-error
// sequence, returned to the client.
func TestForwardFiltered_WriteBan(t *testing.T) {
	t.Parallel()
	in := strings.NewReader("\x01I20100\r\x01S11234\r")
	var upstream, client bytes.Buffer

	err := forwardFiltered(in, &upstream, &client)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("forwardFiltered err = %v, want io.EOF after input drained", err)
	}
	if !bytes.Contains(upstream.Bytes(), []byte("\x01I20100\r")) {
		t.Errorf("the I-command must be forwarded upstream; got %q", upstream.Bytes())
	}
	if bytes.Contains(upstream.Bytes(), []byte("S11234")) {
		t.Errorf("the S (write) command must NOT reach upstream; got %q", upstream.Bytes())
	}
	if client.String() != "9999FF1B\r\n" {
		t.Errorf("the write command must be refused with the data-error sequence; got %q", client.String())
	}
}

// probeAgainstResponder stands up a 127.0.0.1 listener that reads the
// client's query and replies with respond(); it returns the resulting
// finding.
func probeAgainstResponder(t *testing.T, respond func() []byte) *core.Finding {
	t.Helper()
	lc := &net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 64)
		_, _ = conn.Read(buf)
		if reply := respond(); reply != nil {
			_, _ = conn.Write(reply)
		}
	}()
	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("Addr type: got %T", ln.Addr())
	}
	target := core.Target{
		Address: addr.AddrPort().Addr(),
		Port:    core.Port(uint16(addr.Port)), // #nosec G115 -- listener port fits uint16
	}
	plugin := &Plugin{DialTimeout: time.Second, IOTimeout: time.Second}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)
	f, err := plugin.Probe(ctx, target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	return f
}

func TestProbe_PositiveI20100(t *testing.T) {
	t.Parallel()
	f := probeAgainstResponder(t, func() []byte {
		return []byte("\x01I20100\nAPR 15, 2026 10:00\nIN-TANK INVENTORY\n\x03")
	})
	if f.Factors["capability"] != 70 {
		t.Fatalf("capability on an ATG reply: got %d want 70", f.Factors["capability"])
	}
}

func TestProbe_NonATG(t *testing.T) {
	t.Parallel()
	f := probeAgainstResponder(t, func() []byte {
		return []byte("SSH-2.0-OpenSSH_9.0\r\n")
	})
	if f.Factors["capability"] != 30 {
		t.Fatalf("capability on a non-ATG reply: got %d want 30", f.Factors["capability"])
	}
}

func TestProbe_Silent(t *testing.T) {
	t.Parallel()
	f := probeAgainstResponder(t, func() []byte { return nil })
	if f.Factors["capability"] != 30 {
		t.Fatalf("capability on no reply: got %d want 30", f.Factors["capability"])
	}
}

func TestREPLStub(t *testing.T) {
	t.Parallel()
	if err := Default().REPL(context.Background(), nil); err == nil {
		t.Fatal("REPL stub should return an error")
	}
}

// TestProbeEchoIsNotATG: IsATGResponse keys on the I20100 command code, which
// is also our own request, so a service that reflects it must not be
// confirmed as ATG (reproduced against a real echo server in the 2026-10-07
// audit sweep, PITF-071).
func TestProbeEchoIsNotATG(t *testing.T) {
	t.Parallel()
	f := probeAgainstResponder(t, func() []byte {
		return []byte{0x01, 'I', '2', '0', '1', '0', '0', '\r', '\n'}
	})
	if f.Factors["capability"] != 30 {
		t.Fatalf("capability: got %d want 30 (echo is not ATG)", f.Factors["capability"])
	}
}
