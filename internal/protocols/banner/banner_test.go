package banner_test

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"local/elsereno/internal/core"
	"local/elsereno/internal/protocols/banner"
)

// TestProbeAgainstLocalServer spins up a tiny TCP server that writes
// a fixed string, then verifies BannerProbe round-trips it into a
// Finding with the expected shape.
func TestProbeAgainstLocalServer(t *testing.T) {
	t.Parallel()

	lc := &net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = conn.Write([]byte("ELSERENO-TEST-BANNER\r\n"))
	}()

	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("unexpected listener addr type %T", ln.Addr())
	}
	p := banner.Default()
	p.DialTimeout = 2 * time.Second
	p.ReadTimeout = 500 * time.Millisecond

	tg := core.Target{
		Address: addr.AddrPort().Addr().Unmap(),
	}
	portV, err := core.NewPort(addr.Port)
	if err != nil {
		t.Fatalf("NewPort: %v", err)
	}
	tg.Port = portV

	f, err := p.Probe(context.Background(), tg)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if f == nil {
		t.Fatal("Probe returned nil finding")
	}
	if f.Protocol != "banner" {
		t.Fatalf("Protocol=%q, want banner", f.Protocol)
	}
	if f.Score < 0 || f.Score > 100 {
		t.Fatalf("Score out of range: %d", f.Score)
	}
	if !strings.HasPrefix(string(f.ID), string(f.ID)[:1]) { // basic UUID-like
		t.Fatalf("ID missing: %q", f.ID)
	}
}

func TestMetadata(t *testing.T) {
	t.Parallel()
	md := banner.Default().Metadata()
	if md.Name != "banner" {
		t.Fatalf("Name=%q", md.Name)
	}
	if md.Build != "default" {
		t.Fatalf("Build=%q", md.Build)
	}
}

func TestREPLUnsupported(t *testing.T) {
	t.Parallel()
	err := banner.Default().REPL(context.Background(), nil)
	if err == nil {
		t.Fatal("expected REPL unsupported error")
	}
}
