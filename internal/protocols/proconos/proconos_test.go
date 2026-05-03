package proconos

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
	"local/elsereno/internal/protocols/proconos/wire"
)

func TestMetadata(t *testing.T) {
	t.Parallel()
	m := Default().Metadata()
	if m.Name != Name {
		t.Fatalf("Name = %q", m.Name)
	}
	if m.DefaultPort != 20547 {
		t.Fatalf("DefaultPort = %d, want 20547", m.DefaultPort)
	}
	if !strings.Contains(strings.ToLower(m.Description), "best-effort") {
		t.Fatalf("Description should flag best-effort scope: %q", m.Description)
	}
	if !strings.Contains(strings.ToLower(m.Description), "needs real-plc validation") {
		t.Fatalf("Description should call out validation requirement: %q", m.Description)
	}
}

func TestClassifyParseError(t *testing.T) {
	t.Parallel()
	cases := []struct {
		err  error
		want string
	}{
		{wire.ErrShortFrame, "short ProConOS"},
		{wire.ErrNotProConOS, "non-ProConOS reply"},
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
	target := core.Target{Address: netip.MustParseAddr("203.0.113.7"), Port: 20547}
	yes := buildFinding(target, "ProConOS prefix echo", true)
	no := buildFinding(target, "no usable reply", false)
	if yes.Factors["capability"] <= no.Factors["capability"] {
		t.Fatalf("capability should jump on ProConOS reply: yes=%d no=%d",
			yes.Factors["capability"], no.Factors["capability"])
	}
	// Capped lower than codesys/pcworx (75) to reflect best-effort.
	if yes.Factors["capability"] != 60 {
		t.Fatalf("capability cap = %d, want 60 (best-effort)", yes.Factors["capability"])
	}
	if yes.Factors["protocol_risk"] != 75 {
		t.Fatalf("protocol_risk = %d, want 75 (lower than codesys 80, reflects best-effort)", yes.Factors["protocol_risk"])
	}
	if yes.Factors["cve_exposure"] != 7 {
		t.Fatalf("cve_exposure = %d, want 7 (KW-Software / ICSA family)", yes.Factors["cve_exposure"])
	}
}

func probeAgainstResponder(t *testing.T, respond func() []byte) *core.Finding {
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
		buf := make([]byte, wire.HelloLen)
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
		Port:    core.Port(uint16(addr.Port)), // #nosec G115 -- guarded.
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

func TestProbePrefixEcho(t *testing.T) {
	t.Parallel()
	f := probeAgainstResponder(t, func() []byte {
		return append(append([]byte{}, wire.ProConOSHelloPrefix...), 0x00, 0x00, 0x00, 0x10)
	})
	if f.Factors["capability"] != 60 {
		t.Fatalf("capability = %d, want 60", f.Factors["capability"])
	}
}

func TestProbeBannerKWSoftware(t *testing.T) {
	t.Parallel()
	f := probeAgainstResponder(t, func() []byte {
		return []byte("\x00\x00\x00\x00KW-Software MultiProg V5.61")
	})
	if f.Factors["capability"] != 60 {
		t.Fatalf("capability with KW-Software banner = %d, want 60", f.Factors["capability"])
	}
}

func TestProbeBannerProConOS(t *testing.T) {
	t.Parallel()
	f := probeAgainstResponder(t, func() []byte {
		return []byte("\xFF\xFE\xAB\xCDPROCONOS V5.0.0.40 GeneralFirmware")
	})
	if f.Factors["capability"] != 60 {
		t.Fatalf("capability with PROCONOS banner = %d, want 60", f.Factors["capability"])
	}
}

func TestProbeAlternatePrefix(t *testing.T) {
	t.Parallel()
	f := probeAgainstResponder(t, func() []byte {
		// Alt-prefix variant some Berghof/Lenze firmwares emit.
		return []byte{0xCA, 0xFE, 0x00, 0x00, 0xCE, 0xFA, 0xDE, 0xC0, 0x01, 0x02, 0x03, 0x04}
	})
	if f.Factors["capability"] != 60 {
		t.Fatalf("alt-prefix capability = %d, want 60", f.Factors["capability"])
	}
}

func TestProbeSilentResponder(t *testing.T) {
	t.Parallel()
	f := probeAgainstResponder(t, func() []byte { return nil })
	if f.Factors["capability"] != 30 {
		t.Fatalf("silent: capability = %d, want 30", f.Factors["capability"])
	}
}

func TestProbeNonProConOS(t *testing.T) {
	t.Parallel()
	f := probeAgainstResponder(t, func() []byte {
		return []byte("HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n")
	})
	if f.Factors["capability"] != 30 {
		t.Fatalf("non-ProConOS: capability = %d, want 30", f.Factors["capability"])
	}
}

func TestProxyHandlerFailClosed(t *testing.T) {
	t.Parallel()
	h := Default().ProxyHandler()
	err := h.Handle(context.Background(), nil, nil)
	if err == nil {
		t.Fatal("ProxyHandler should refuse")
	}
	if !strings.Contains(err.Error(), "real-PLC validation") {
		t.Fatalf("error should call out PLC-validation requirement: %v", err)
	}
}

func TestREPLStub(t *testing.T) {
	t.Parallel()
	if err := Default().REPL(context.Background(), nil); err == nil {
		t.Fatal("REPL stub should return an error")
	}
}
