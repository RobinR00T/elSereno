package s7_test

import (
	"context"
	"net"
	"testing"
	"time"

	"local/elsereno/internal/core"
	"local/elsereno/internal/protocols/s7"
	"local/elsereno/internal/protocols/s7/wire"
)

func simulator(t *testing.T, replyCOTP []byte) *net.TCPAddr {
	t.Helper()
	lc := &net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("addr type %T", ln.Addr())
	}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = wire.ReadTPKT(conn)
		if replyCOTP == nil {
			return
		}
		_ = wire.WriteTPKT(conn, replyCOTP)
	}()
	return addr
}

func TestProbeCOTPConfirm(t *testing.T) {
	t.Parallel()
	// CC reply: LI=0x11, type=0xD0, DstRef 0x00 0x01, SrcRef 0x00 0x02, class 0x00
	cc := []byte{0x11, 0xD0, 0x00, 0x01, 0x00, 0x02, 0x00,
		0xC1, 0x02, 0x01, 0x00, 0xC2, 0x02, 0x01, 0x02, 0xC0, 0x01, 0x0A,
	}
	addr := simulator(t, cc)
	p := s7.Default()
	p.DialTimeout = 2 * time.Second
	p.IOTimeout = 500 * time.Millisecond
	port, _ := core.NewPort(addr.Port)
	tg := core.Target{Address: addr.AddrPort().Addr().Unmap(), Port: port}
	f, err := p.Probe(context.Background(), tg)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if f.Protocol != s7.Name {
		t.Fatalf("Protocol=%q", f.Protocol)
	}
	if f.Factors["capability"] < 50 {
		t.Fatalf("capability=%d, want >=50 on CC", f.Factors["capability"])
	}
}

func TestProbeSilent(t *testing.T) {
	t.Parallel()
	addr := simulator(t, nil)
	p := s7.Default()
	p.DialTimeout = 2 * time.Second
	p.IOTimeout = 200 * time.Millisecond
	port, _ := core.NewPort(addr.Port)
	tg := core.Target{Address: addr.AddrPort().Addr().Unmap(), Port: port}
	_, err := p.Probe(context.Background(), tg)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
}

func TestMetadata(t *testing.T) {
	t.Parallel()
	md := s7.Default().Metadata()
	if md.Name != s7.Name {
		t.Fatalf("Name=%q", md.Name)
	}
	if md.DefaultPort != 102 {
		t.Fatalf("DefaultPort=%d", md.DefaultPort)
	}
}
