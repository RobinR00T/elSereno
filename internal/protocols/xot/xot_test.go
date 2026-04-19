package xot_test

import (
	"context"
	"net"
	"testing"
	"time"

	"local/elsereno/internal/core"
	"local/elsereno/internal/protocols/xot"
	"local/elsereno/internal/protocols/xot/wire"
)

// dceSim listens on 127.0.0.1:0 and replies to the first XOT frame
// with a Clear Indication (cause 0x00, diag 0x00).
func dceSim(t *testing.T, respond func(packet wire.Packet) []byte) *net.TCPAddr {
	t.Helper()
	lc := &net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("unexpected addr type %T", ln.Addr())
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				packet, err := wire.ReadXOTFrame(c)
				if err != nil {
					return
				}
				resp := respond(packet)
				if resp == nil {
					return
				}
				_ = wire.WriteXOTFrame(c, resp)
			}(conn)
		}
	}()
	return addr
}

func TestProbeClearIndication(t *testing.T) {
	t.Parallel()
	addr := dceSim(t, func(_ wire.Packet) []byte {
		return []byte{0x10, 0x01, uint8(wire.PacketClearRequest), 0x05, 0x01}
	})

	p := xot.Default()
	p.DialTimeout = 2 * time.Second
	p.IOTimeout = 1 * time.Second

	port, _ := core.NewPort(addr.Port)
	tg := core.Target{Address: addr.AddrPort().Addr().Unmap(), Port: port}

	f, err := p.Probe(context.Background(), tg)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if f.Protocol != xot.Name {
		t.Fatalf("Protocol=%q", f.Protocol)
	}
	if f.Score < 0 || f.Score > 100 {
		t.Fatalf("Score out of range: %d", f.Score)
	}
}

func TestProbeCallAcceptedBumpsCapability(t *testing.T) {
	t.Parallel()
	addr := dceSim(t, func(_ wire.Packet) []byte {
		return []byte{0x10, 0x01, uint8(wire.PacketCallAccepted), 0x00, 0x00}
	})
	p := xot.Default()
	p.DialTimeout = 2 * time.Second
	p.IOTimeout = 1 * time.Second
	port, _ := core.NewPort(addr.Port)
	tg := core.Target{Address: addr.AddrPort().Addr().Unmap(), Port: port}
	f, err := p.Probe(context.Background(), tg)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if f.Factors["capability"] < 50 {
		t.Fatalf("capability=%d, want >=50 for CALL_ACCEPTED", f.Factors["capability"])
	}
}

func TestProbeSilentRejectEmitsInfo(t *testing.T) {
	t.Parallel()
	addr := dceSim(t, func(_ wire.Packet) []byte {
		return nil // close without responding
	})
	p := xot.Default()
	p.DialTimeout = 2 * time.Second
	p.IOTimeout = 500 * time.Millisecond
	port, _ := core.NewPort(addr.Port)
	tg := core.Target{Address: addr.AddrPort().Addr().Unmap(), Port: port}
	f, err := p.Probe(context.Background(), tg)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if f.Severity != core.SeverityInfo && f.Severity != core.SeverityLow {
		t.Fatalf("Severity=%s; want info or low for silent reject", f.Severity)
	}
}

func TestMetadata(t *testing.T) {
	t.Parallel()
	md := xot.Default().Metadata()
	if md.Name != xot.Name {
		t.Fatalf("Name=%q", md.Name)
	}
	if md.DefaultPort != xot.DefaultPort {
		t.Fatalf("DefaultPort=%d", md.DefaultPort)
	}
}
