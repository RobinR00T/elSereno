package dnp3_test

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"local/elsereno/internal/core"
	"local/elsereno/internal/protocols/dnp3"
	"local/elsereno/internal/protocols/dnp3/wire"
)

// serveOnce accepts one connection, hands it to handle and closes it. It
// returns the probe target.
func serveOnce(t *testing.T, handle func(net.Conn)) core.Target {
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
		handle(conn)
	}()
	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok || addr.Port <= 0 || addr.Port > 0xFFFF {
		t.Fatalf("unexpected listener address %v", ln.Addr())
	}
	return core.Target{
		Address: addr.AddrPort().Addr(),
		Port:    core.Port(uint16(addr.Port)), // #nosec G115 -- range-checked above.
	}
}

// outstation behaves like a real DNP3 outstation at link address own: it
// discards every frame whose header CRC is wrong or that is addressed
// elsewhere, and answers a Request Link Status with a Link Status
// (secondary function 11) back to the requesting master.
func outstation(own uint16) func(net.Conn) {
	return func(c net.Conn) {
		hdr := make([]byte, wire.HeaderLen)
		for {
			if _, err := io.ReadFull(c, hdr); err != nil {
				return
			}
			h, err := wire.ParseHeader(hdr)
			if err != nil {
				return
			}
			if n := wire.BodyLen(h.Length); n > 0 {
				if _, err := io.CopyN(io.Discard, c, int64(n)); err != nil {
					return
				}
			}
			if !wire.ValidHeader(hdr) || h.Dest != own || h.Control != wire.RequestLinkStatusControl {
				continue
			}
			resp := []byte{0x05, 0x64, 0x05, 0x0B, 0, 0, 0, 0, 0, 0}
			binary.LittleEndian.PutUint16(resp[4:6], h.Src)
			binary.LittleEndian.PutUint16(resp[6:8], own)
			binary.LittleEndian.PutUint16(resp[8:10], wire.CRC16(resp[:8]))
			_, _ = c.Write(resp)
		}
	}
}

func probe(t *testing.T, target core.Target) int {
	t.Helper()
	p := dnp3.Default()
	p.DialTimeout = time.Second
	p.IOTimeout = time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	f, err := p.Probe(ctx, target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	return f.Factors["capability"]
}

// TestProbeFindsOutstationByAddressSweep: an outstation answers only its
// own link address and only a correct CRC. Address 5 is the outstation's
// address in the CISA icsnpp-dnp3 capture. The previous probe (a zero-CRC
// header to address 1) got no answer from it (PITF-073).
func TestProbeFindsOutstationByAddressSweep(t *testing.T) {
	t.Parallel()
	for _, own := range []uint16{0, 5, wire.SweepLastDest} {
		if got := probe(t, serveOnce(t, outstation(own))); got != 70 {
			t.Errorf("outstation at address %d: capability %d, want 70", own, got)
		}
	}
}

// TestProbeCorruptReplyIsNotDNP3: 05 64 followed by a wrong header CRC is
// not a DNP3 frame; no outstation sends one.
func TestProbeCorruptReplyIsNotDNP3(t *testing.T) {
	t.Parallel()
	target := serveOnce(t, func(c net.Conn) {
		_, _ = c.Read(make([]byte, 2048))
		_, _ = c.Write([]byte{0x05, 0x64, 0x05, 0x0B, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00})
	})
	if got := probe(t, target); got != 30 {
		t.Fatalf("capability %d, want 30 (corrupt CRC is not DNP3)", got)
	}
}
