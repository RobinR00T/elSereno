package tristation

import (
	"context"
	"encoding/hex"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"local/elsereno/internal/core"
	"local/elsereno/internal/protocols/tristation/wire"
)

// fakeController answers CONNECT with reply and Get CP status with the
// captured status datagram. It returns its port.
func fakeController(t *testing.T, reply []byte) core.Port {
	t.Helper()
	b, err := os.ReadFile("wire/testdata/cp_status_response.hex")
	if err != nil {
		t.Fatal(err)
	}
	status, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	pc, err := (&net.ListenConfig{}).ListenPacket(context.Background(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot bind loopback UDP: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			switch buf[0] {
			case wire.OpConnectRequest:
				_, _ = pc.WriteTo(reply, from)
			case wire.OpCommand:
				if n > 6 && buf[6] == wire.CmdGetCPStatus {
					_, _ = pc.WriteTo(status, from)
				}
			}
		}
	}()
	return udpPort(t, pc)
}

func quick() *Plugin { return &Plugin{DialTimeout: time.Second, IOTimeout: 500 * time.Millisecond} }

func TestProbeAndStatus(t *testing.T) {
	connectReply, _ := hex.DecodeString("0200000001b8")
	port := fakeController(t, connectReply)
	target := core.Target{Address: netip.MustParseAddr("127.0.0.1"), Port: port}
	f, err := quick().Probe(context.Background(), target)
	if err != nil || f.Factors["capability"] != 80 || f.Protocol != Name {
		t.Fatalf("probe: %+v %v", f, err)
	}
	s, err := quick().Open(context.Background(), net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	st, err := s.Status()
	if err != nil || st.Project != "NOZOMI" || st.KeyName != "PROGRAM" || st.RunName != "RUNNING" {
		t.Fatalf("status: %+v %v", st, err)
	}
}

func TestProbeRefusedAndSilent(t *testing.T) {
	limit := []byte{wire.OpConnLimitReached, 0, 0, 0}
	limit = binaryAppendCRC(limit)
	port := fakeController(t, limit)
	f, err := quick().Probe(context.Background(), core.Target{Address: netip.MustParseAddr("127.0.0.1"), Port: port})
	if err != nil || f.Factors["capability"] != 80 {
		t.Fatalf("refused: %+v %v", f, err)
	}
	pc, err := (&net.ListenConfig{}).ListenPacket(context.Background(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer func() { _ = pc.Close() }()
	silent := udpPort(t, pc)
	f, err = quick().Probe(context.Background(), core.Target{Address: netip.MustParseAddr("127.0.0.1"), Port: silent})
	if err != nil || f.Factors["capability"] != 30 {
		t.Fatalf("silent: %+v %v", f, err)
	}
}

func udpPort(t *testing.T, c net.PacketConn) core.Port {
	t.Helper()
	a, ok := c.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("listener addr is not UDP: %T", c.LocalAddr())
	}
	return core.Port(a.Port) // #nosec G115 -- loopback test port
}

func binaryAppendCRC(b []byte) []byte {
	c := wire.CRC16(b)
	return append(b, byte(c&0xff), byte(c>>8&0xff))
}

func TestMetadataOptIn(t *testing.T) {
	m := Default().Metadata()
	if !m.OptIn || m.DefaultPort != 0 {
		t.Fatalf("tristation must be opt-in: %+v", m)
	}
	if Default().ProxyHandler().Handle(context.Background(), nil, nil) == nil {
		t.Fatal("proxy must fail closed")
	}
}
