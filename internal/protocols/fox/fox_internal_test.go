package fox

import (
	"bytes"
	"context"
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
	if m.DefaultPort != 1911 {
		t.Fatalf("DefaultPort: got %d want 1911", m.DefaultPort)
	}
	if !strings.Contains(strings.ToLower(m.Description), "niagara") {
		t.Fatalf("Description should mention Niagara: %q", m.Description)
	}
}

func TestBuildFindingFactors(t *testing.T) {
	t.Parallel()
	target := core.Target{Address: netip.MustParseAddr("203.0.113.11"), Port: 1911}
	yes := buildFinding(target, "fox banner detected", true)
	no := buildFinding(target, "no fox banner", false)

	if yes.Factors["capability"] <= no.Factors["capability"] {
		t.Fatalf("capability should jump on a fox banner: yes=%d no=%d",
			yes.Factors["capability"], no.Factors["capability"])
	}
	if yes.Factors["cve_exposure"] != 13 {
		t.Fatalf("cve_exposure: got %d want 13", yes.Factors["cve_exposure"])
	}
	if yes.Factors["protocol_risk"] != 80 {
		t.Fatalf("protocol_risk: got %d want 80", yes.Factors["protocol_risk"])
	}
	if yes.Protocol != Name {
		t.Fatalf("Protocol: got %q want %q", yes.Protocol, Name)
	}
	if yes.ID == no.ID {
		t.Fatal("distinct notes must give distinct ids")
	}
}

// probeAgainstBanner stands up a listener that behaves like a Niagara
// station: it says nothing until the client sends a hello ("fox a 1 ..."),
// then writes banner, and returns the probe's finding. (Until 2026-10-07
// this helper wrote the banner on connect, which no real station does,
// and so hid a probe that never said hello; PITF-078.)
func probeAgainstBanner(t *testing.T, banner []byte) *core.Finding {
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
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		got := make([]byte, 512)
		n, _ := conn.Read(got)
		if !bytes.HasPrefix(got[:n], []byte("fox a 1 ")) {
			return // a station ignores anything but a client hello
		}
		if banner != nil {
			_, _ = conn.Write(banner)
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

func TestProbe_FoxBanner(t *testing.T) {
	t.Parallel()
	f := probeAgainstBanner(t, []byte("fox a 0 -1 fox hello\n{fox.version=1.0.1}\n"))
	if f.Factors["capability"] != 70 {
		t.Fatalf("capability on a fox banner: got %d want 70", f.Factors["capability"])
	}
}

func TestProbe_NonFox(t *testing.T) {
	t.Parallel()
	f := probeAgainstBanner(t, []byte("SSH-2.0-OpenSSH_9.0\r\n"))
	if f.Factors["capability"] != 30 {
		t.Fatalf("capability on a non-fox banner: got %d want 30", f.Factors["capability"])
	}
}

// The default proxy refuses all client input with a fox-native denial
// line, written back to the client.
func TestProxyHandler_DenyAll(t *testing.T) {
	t.Parallel()
	var client bytes.Buffer
	err := Default().ProxyHandler().Handle(context.Background(), &client, nil)
	if err == nil {
		t.Fatal("the default fox proxy must refuse client input")
	}
	if !strings.Contains(client.String(), "fox denied") {
		t.Fatalf("client should receive the fox denial line; got %q", client.String())
	}
}

func TestREPLStub(t *testing.T) {
	t.Parallel()
	if err := Default().REPL(context.Background(), nil); err == nil {
		t.Fatal("REPL stub should return an error")
	}
}
