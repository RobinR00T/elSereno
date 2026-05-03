package iax2_test

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"local/elsereno/internal/core"
	"local/elsereno/internal/protocols/iax2"
	"local/elsereno/internal/protocols/iax2/wire"
)

// udpResponder listens on a loopback UDP port, reads one
// packet, writes the supplied frame back. Returns the bound
// port + a stop func. All tests use this same shape.
func udpResponder(t *testing.T, reply []byte) (int, func()) {
	t.Helper()
	lc := net.ListenConfig{}
	ctx, cancel := context.WithCancel(context.Background())
	conn, err := lc.ListenPacket(ctx, "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 4096)
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, addr, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		_, _ = conn.WriteTo(reply, addr)
	}()
	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("LocalAddr not UDPAddr: %T", conn.LocalAddr())
	}
	return addr.Port, func() { cancel(); _ = conn.Close() }
}

// buildReply forges an IAX2 full-frame reply with the given
// subclass.
func buildReply(sub wire.IAXSubclass, srcCall uint16, dstCall uint16) []byte {
	b := make([]byte, wire.HeaderLen)
	b[0] = 0x80 | byte((srcCall>>8)&0x7F)
	b[1] = byte(srcCall & 0xFF)
	b[2] = byte((dstCall >> 8) & 0x7F)
	b[3] = byte(dstCall & 0xFF)
	// Timestamp 0, OSeqno/ISeqno 0
	b[10] = byte(wire.FrameTypeIAX)
	b[11] = byte(sub)
	return b
}

func probeAt(t *testing.T, port int) *core.Finding {
	t.Helper()
	plug := iax2.Default()
	plug.DialTimeout = 1 * time.Second
	plug.IOTimeout = 1 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	f, err := plug.Probe(ctx, core.Target{
		Address: netip.MustParseAddr("127.0.0.1"),
		Port:    core.Port(port), // #nosec G115 -- test port in loopback range
	})
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	return f
}

func TestProbe_AuthReqConfirmsIAX2(t *testing.T) {
	reply := buildReply(wire.IAXAuthReq, 0x1234, 0x5678)
	port, stop := udpResponder(t, reply)
	defer stop()
	f := probeAt(t, port)
	if f.Factors["protocol_risk"] != 90 {
		t.Fatalf("protocol_risk = %d, want 90", f.Factors["protocol_risk"])
	}
	if f.Factors["capability"] != 60 {
		t.Fatalf("capability = %d, want 60", f.Factors["capability"])
	}
	// auth_state drops to 50 when AUTHREQ is seen.
	if f.Factors["auth_state"] != 50 {
		t.Fatalf("auth_state = %d, want 50", f.Factors["auth_state"])
	}
}

func TestProbe_AcceptConfirmsIAX2(t *testing.T) {
	port, stop := udpResponder(t, buildReply(wire.IAXAccept, 0x1111, 0x2222))
	defer stop()
	f := probeAt(t, port)
	if f.Factors["protocol_risk"] != 90 {
		t.Fatalf("protocol_risk = %d, want 90", f.Factors["protocol_risk"])
	}
	// ACCEPT means the remote picked up — no 401, so
	// auth_state stays at the default 60.
	if f.Factors["auth_state"] != 60 {
		t.Fatalf("auth_state = %d, want 60", f.Factors["auth_state"])
	}
}

func TestProbe_NonIAX2Bytes(t *testing.T) {
	// Reply with non-IAX2 junk (HTTP).
	port, stop := udpResponder(t, []byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
	defer stop()
	f := probeAt(t, port)
	if f.Factors["protocol_risk"] != 70 {
		t.Fatalf("non-IAX2 protocol_risk = %d, want 70 (default)", f.Factors["protocol_risk"])
	}
	if f.Factors["capability"] != 30 {
		t.Fatalf("non-IAX2 capability = %d, want 30", f.Factors["capability"])
	}
}

func TestProbe_RejectConfirmsIAX2(t *testing.T) {
	port, stop := udpResponder(t, buildReply(wire.IAXReject, 0xAAAA, 0xBBBB))
	defer stop()
	f := probeAt(t, port)
	if f.Factors["protocol_risk"] != 90 {
		t.Fatalf("REJECT should still confirm IAX2 → risk=90, got %d", f.Factors["protocol_risk"])
	}
}

func TestMetadata_Port4569(t *testing.T) {
	meta := iax2.Default().Metadata()
	if meta.DefaultPort != 4569 {
		t.Fatalf("port = %d, want 4569", meta.DefaultPort)
	}
	if meta.Name != "iax2" {
		t.Fatalf("name = %q", meta.Name)
	}
}
