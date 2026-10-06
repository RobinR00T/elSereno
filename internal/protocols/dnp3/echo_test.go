package dnp3_test

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"local/elsereno/internal/core"
	"local/elsereno/internal/protocols/dnp3"
)

// tcpEcho accepts one connection and reflects whatever the client sends,
// like a TCP echo service, then closes. It returns the probe target.
func tcpEcho(t *testing.T) core.Target {
	t.Helper()
	lc := &net.ListenConfig{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	ln, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
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
		_, _ = io.CopyN(conn, conn, 4096)
	}()
	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("Addr type: got %T", ln.Addr())
	}
	if addr.Port < 0 || addr.Port > 0xFFFF {
		t.Fatalf("port out of range: %d", addr.Port)
	}
	return core.Target{
		Address: addr.AddrPort().Addr(),
		Port:    core.Port(uint16(addr.Port)), // #nosec G115 -- guarded.
	}
}

// TestProbeEchoIsNotDNP3: every DNP3 link frame opens with 05 64 in both directions, so a reflected Read Class 0 passed IsDNP3Frame (PITF-071).
func TestProbeEchoIsNotDNP3(t *testing.T) {
	t.Parallel()
	p := dnp3.Default()
	p.DialTimeout = time.Second
	p.IOTimeout = time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	f, err := p.Probe(ctx, tcpEcho(t))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if f.Factors["capability"] != 30 {
		t.Fatalf("capability: got %d want 30 (echo is not DNP3)", f.Factors["capability"])
	}
}
