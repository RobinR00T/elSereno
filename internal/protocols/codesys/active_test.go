package codesys

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"local/elsereno/internal/core"
	"local/elsereno/internal/protocols/codesys/wire"
)

func TestActiveMetadataOptIn(t *testing.T) {
	t.Parallel()
	m := DefaultActive().Metadata()
	if m.Name != ActiveName {
		t.Fatalf("Name: got %q want %q", m.Name, ActiveName)
	}
	if m.DefaultPort != 0 {
		t.Fatalf("DefaultPort: got %d want 0 (opt-in)", m.DefaultPort)
	}
	if !m.OptIn {
		t.Fatal("ActivePlugin must be OptIn so the default sweep skips it")
	}
}

func activeProbeAgainstResponder(t *testing.T, respond func(req []byte) []byte) *core.Finding {
	t.Helper()
	lc := &net.ListenConfig{}
	lctx, lcancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(lcancel)
	ln, err := lc.Listen(lctx, "tcp", "127.0.0.1:0")
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
		// Read the channel-open request, then reply (the responder sees it,
		// so a test can reflect it like an echo service would).
		req := make([]byte, len(wire.BuildChannelOpen(1)))
		_, _ = io.ReadFull(conn, req)
		if reply := respond(req); reply != nil {
			_, _ = conn.Write(reply)
		}
	}()
	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("Addr type: got %T", ln.Addr())
	}
	if addr.Port < 0 || addr.Port > 0xFFFF {
		t.Fatalf("port out of range: %d", addr.Port)
	}
	target := core.Target{
		Address: addr.AddrPort().Addr(),
		Port:    core.Port(uint16(addr.Port)), // #nosec G115 -- guarded.
	}
	plugin := &ActivePlugin{DialTimeout: 1 * time.Second, IOTimeout: 1 * time.Second}
	pctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	f, err := plugin.Probe(pctx, target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	return f
}

func TestActiveProbeBlockDriverReply(t *testing.T) {
	t.Parallel()
	// Gateway replies with a Block-Driver-framed response (magic echo).
	f := activeProbeAgainstResponder(t, func([]byte) []byte {
		return append([]byte(nil), append(wire.BlockDriverMagic, 0x10, 0x00, 0x00, 0x00)...)
	})
	if f.Factors["capability"] != 70 {
		t.Fatalf("capability: got %d want 70 (confirmed CoDeSys)", f.Factors["capability"])
	}
	// Findings carry the opt-in plugin's own name (like s7-exposure), not
	// the default plugin's, so they stay distinguishable in every output.
	if f.Protocol != ActiveName {
		t.Fatalf("Protocol: got %q want %q", f.Protocol, ActiveName)
	}
}

// TestActiveProbeEchoIsNotCoDeSys: a reflecting service hands back our own
// magic-prefixed channel-open frame; that must not confirm CoDeSys.
func TestActiveProbeEchoIsNotCoDeSys(t *testing.T) {
	t.Parallel()
	f := activeProbeAgainstResponder(t, func(req []byte) []byte { return req })
	if f.Factors["capability"] != 30 {
		t.Fatalf("capability: got %d want 30 (full echo is not CoDeSys)", f.Factors["capability"])
	}
}

// TestActiveProbePartialEchoIsNotCoDeSys: an echo cut short by a TCP read
// boundary is still a prefix of the probe and must be rejected too.
func TestActiveProbePartialEchoIsNotCoDeSys(t *testing.T) {
	t.Parallel()
	f := activeProbeAgainstResponder(t, func(req []byte) []byte { return req[:20] })
	if f.Factors["capability"] != 30 {
		t.Fatalf("capability: got %d want 30 (partial echo is not CoDeSys)", f.Factors["capability"])
	}
}

func TestActiveProbeSilent(t *testing.T) {
	t.Parallel()
	f := activeProbeAgainstResponder(t, func([]byte) []byte { return nil })
	if f.Factors["capability"] != 30 {
		t.Fatalf("capability: got %d want 30 (no reply)", f.Factors["capability"])
	}
}

func TestActiveProbeNonCoDeSys(t *testing.T) {
	t.Parallel()
	f := activeProbeAgainstResponder(t, func([]byte) []byte {
		return []byte("HTTP/1.1 400 Bad Request\r\n\r\n")
	})
	if f.Factors["capability"] != 30 {
		t.Fatalf("capability: got %d want 30 (non-CoDeSys)", f.Factors["capability"])
	}
}

func TestActiveREPLAndProxyStubs(t *testing.T) {
	t.Parallel()
	if err := DefaultActive().REPL(context.Background(), nil); err == nil {
		t.Fatal("REPL stub should error")
	}
	if err := DefaultActive().ProxyHandler().Handle(context.Background(), nil, nil); err == nil {
		t.Fatal("ProxyHandler should refuse")
	}
}
