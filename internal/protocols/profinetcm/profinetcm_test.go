package profinetcm

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"local/elsereno/internal/core"
	"local/elsereno/internal/protocols/profinetcm/wire"
)

// fakeDevice answers from a DIFFERENT port than the one it listens on,
// like a real PNIO device, echoing the request's activity id.
func fakeDevice(t *testing.T, ptype byte) core.Port {
	t.Helper()
	lc := &net.ListenConfig{}
	in, err := lc.ListenPacket(context.Background(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot bind loopback UDP: %v", err)
	}
	out, err := lc.ListenPacket(context.Background(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { _ = in.Close(); _ = out.Close() })
	go func() {
		buf := make([]byte, 1500)
		n, from, err := in.ReadFrom(buf)
		if err != nil || n < 80 {
			return
		}
		rep := make([]byte, 80)
		rep[0], rep[1], rep[4] = 4, ptype, 0x10
		copy(rep[40:56], buf[40:56])
		annot := "S7-1500                   6ES7 672-5DC01-0YA0      0 V  2  1  7"
		body := make([]byte, 20)
		for _, v := range []uint32{1, 1, 0, 1} {
			body = binary.LittleEndian.AppendUint32(body, v)
		}
		body = append(body, make([]byte, 16)...)
		body = binary.LittleEndian.AppendUint32(body, 3)
		body = binary.LittleEndian.AppendUint32(body, 0)
		annotLen := uint32(len(annot)) // #nosec G115 -- fixed test string, length fits
		body = binary.LittleEndian.AppendUint32(body, annotLen)
		body = append(body, annot...)
		_, _ = out.WriteTo(append(rep, body...), from)
	}()
	udp, ok := in.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("listener addr is not UDP: %T", in.LocalAddr())
	}
	return core.Port(udp.Port) // #nosec G115 -- loopback test port
}

func TestProbe(t *testing.T) {
	p := &Plugin{IOTimeout: time.Second}
	addr := netip.MustParseAddr("127.0.0.1")
	f, err := p.Probe(context.Background(), core.Target{Address: addr, Port: fakeDevice(t, wire.PTypeResponse)})
	if err != nil || f.Factors["capability"] != 80 {
		t.Fatalf("%+v %v", f, err)
	}
	r, err := p.Lookup(context.Background(), core.Target{Address: addr, Port: fakeDevice(t, wire.PTypeResponse)})
	if err != nil || r.OrderID != "6ES7 672-5DC01-0YA0" {
		t.Fatalf("%+v %v", r, err)
	}
	f, _ = p.Probe(context.Background(), core.Target{Address: addr, Port: fakeDevice(t, wire.PTypeReject)})
	if f.Factors["capability"] != 55 {
		t.Fatalf("reject: %+v", f)
	}
	if !Default().Metadata().OptIn || Default().ProxyHandler().Handle(context.Background(), nil, nil) == nil {
		t.Fatal("must be opt-in and fail closed")
	}
}
