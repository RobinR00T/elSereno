package redlion

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"local/elsereno/internal/core"
	"local/elsereno/internal/protocols/redlion/wire"
)

func TestMetadata(t *testing.T) {
	t.Parallel()
	m := Default().Metadata()
	if m.Name != Name {
		t.Fatalf("Name: got %q", m.Name)
	}
	if m.DefaultPort != 789 {
		t.Fatalf("DefaultPort: got %d", m.DefaultPort)
	}
	if !strings.Contains(m.Description, "Red Lion") {
		t.Fatalf("Description should mention Red Lion: %q", m.Description)
	}
}

func TestClassifyParseError(t *testing.T) {
	t.Parallel()
	cases := []struct {
		err  error
		want string
	}{
		{wire.ErrShortFrame, "short Red Lion"},
		{wire.ErrNotRedLion, "non-Red-Lion"},
		{errors.New("anything else"), "classify failure"},
	}
	for _, c := range cases {
		got := classifyParseError(c.err)
		if !strings.Contains(got, c.want) {
			t.Fatalf("classifyParseError(%v) = %q want substring %q", c.err, got, c.want)
		}
	}
}

func TestBuildFindingFactors(t *testing.T) {
	t.Parallel()
	target := core.Target{
		Address: netip.MustParseAddr("203.0.113.7"),
		Port:    789,
	}
	yes := buildFinding(target, "Red Lion banner=Crimson 3", true)
	no := buildFinding(target, "no usable reply", false)
	if yes.Factors["capability"] <= no.Factors["capability"] {
		t.Fatalf("capability should jump on Red Lion reply: yes=%d no=%d",
			yes.Factors["capability"], no.Factors["capability"])
	}
	if yes.Factors["cve_exposure"] != 5 {
		t.Fatalf("cve_exposure: got %d want 5", yes.Factors["cve_exposure"])
	}
}

func probeAgainstResponder(t *testing.T, unsolicited bool, respond func() []byte) *core.Finding {
	t.Helper()
	listenerCtx, listenerCancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(listenerCancel)
	lc := &net.ListenConfig{}
	listener, err := lc.Listen(listenerCtx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		if unsolicited {
			if reply := respond(); reply != nil {
				_, _ = conn.Write(reply)
			}
			return
		}
		// Wait for the 3-byte hello, then reply.
		buf := make([]byte, 3)
		_, _ = io.ReadFull(conn, buf)
		if reply := respond(); reply != nil {
			_, _ = conn.Write(reply)
		}
	}()
	addr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("Addr type: got %T", listener.Addr())
	}
	if addr.Port < 0 || addr.Port > 0xFFFF {
		t.Fatalf("port out of range: %d", addr.Port)
	}
	target := core.Target{
		Address: addr.AddrPort().Addr(),
		Port:    core.Port(uint16(addr.Port)), //nolint:gosec // G115 — guarded.
	}
	plugin := &Plugin{DialTimeout: 1 * time.Second, IOTimeout: 1 * time.Second}
	probeCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)
	f, err := plugin.Probe(probeCtx, target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	return f
}

func TestProbeUnsolicitedBanner(t *testing.T) {
	t.Parallel()
	f := probeAgainstResponder(t, true, func() []byte {
		return []byte("\x00 Red Lion Controls G3 HMI Crimson 3.1 SP18\r\n")
	})
	if f.Factors["capability"] != 70 {
		t.Fatalf("capability: got %d want 70", f.Factors["capability"])
	}
}

func TestProbeBannerAfterHello(t *testing.T) {
	t.Parallel()
	f := probeAgainstResponder(t, false, func() []byte {
		return []byte("FlexEdge-CORE-RTC fw=20240115\n")
	})
	if f.Factors["capability"] != 70 {
		t.Fatalf("capability: got %d want 70", f.Factors["capability"])
	}
}

func TestProbeSilentResponder(t *testing.T) {
	t.Parallel()
	f := probeAgainstResponder(t, false, func() []byte { return nil })
	if f.Factors["capability"] != 30 {
		t.Fatalf("capability: got %d want 30 (no reply)", f.Factors["capability"])
	}
}

func TestProbeNonRedLion(t *testing.T) {
	t.Parallel()
	f := probeAgainstResponder(t, false, func() []byte {
		return []byte("HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n")
	})
	if f.Factors["capability"] != 30 {
		t.Fatalf("capability: got %d want 30 (non-Red-Lion)", f.Factors["capability"])
	}
}

func TestProxyHandlerFailClosed(t *testing.T) {
	t.Parallel()
	h := Default().ProxyHandler()
	err := h.Handle(context.Background(), nil, nil)
	if err == nil {
		t.Fatal("ProxyHandler should refuse")
	}
	if !strings.Contains(err.Error(), "fingerprint-only") {
		t.Fatalf("error should mention fingerprint-only: %v", err)
	}
}

func TestREPLStub(t *testing.T) {
	t.Parallel()
	if err := Default().REPL(context.Background(), nil); err == nil {
		t.Fatal("REPL stub should return an error")
	}
}
