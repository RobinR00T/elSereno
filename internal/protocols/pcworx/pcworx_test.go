package pcworx

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
	"local/elsereno/internal/protocols/pcworx/wire"
)

func TestMetadata(t *testing.T) {
	t.Parallel()
	m := Default().Metadata()
	if m.Name != Name {
		t.Fatalf("Name: got %q", m.Name)
	}
	if m.DefaultPort != 1962 {
		t.Fatalf("DefaultPort: got %d want 1962", m.DefaultPort)
	}
	if !strings.Contains(strings.ToLower(m.Description), "pcworx") {
		t.Fatalf("Description should mention PCWorx: %q", m.Description)
	}
	if !strings.Contains(strings.ToLower(m.Description), "phoenix") {
		t.Fatalf("Description should mention Phoenix Contact: %q", m.Description)
	}
}

func TestClassifyParseError(t *testing.T) {
	t.Parallel()
	cases := []struct {
		err  error
		want string
	}{
		{wire.ErrShortFrame, "short PCWorx"},
		{wire.ErrNotPCWorx, "non-PCWorx reply"},
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
		Port:    1962,
	}
	yes := buildFinding(target, "PCWorx prefix echo", true)
	no := buildFinding(target, "no usable reply", false)
	if yes.Factors["capability"] <= no.Factors["capability"] {
		t.Fatalf("capability should jump on PCWorx reply: yes=%d no=%d",
			yes.Factors["capability"], no.Factors["capability"])
	}
	if yes.Factors["cve_exposure"] != 8 {
		t.Fatalf("cve_exposure: got %d want 8 (ICSA-15-160-01 / 17-201-01 / 21-082-01 + ILC CVE family)", yes.Factors["cve_exposure"])
	}
	if yes.Factors["protocol_risk"] != 80 {
		t.Fatalf("protocol_risk: got %d want 80", yes.Factors["protocol_risk"])
	}
}

// probeAgainstResponder spins up a 127.0.0.1 listener that
// reads the 32-byte hello and replies with whatever respond()
// returns. Same shape as codesys_test.go's helper so the suite
// stays uniform.
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

func TestProbePrefixEcho(t *testing.T) {
	t.Parallel()
	f := probeAgainstResponder(t, func() []byte {
		// 4-byte prefix echo + arbitrary payload.
		return append(append([]byte{}, wire.PCWorxHelloPrefix...), 0x00, 0x00, 0x00, 0x10)
	})
	if f.Factors["capability"] != 70 {
		t.Fatalf("capability: got %d want 70", f.Factors["capability"])
	}
}

func TestProbeBannerILC(t *testing.T) {
	t.Parallel()
	f := probeAgainstResponder(t, func() []byte {
		return []byte("\x00\x00\x00\x00ILC 350 PN\x00FW V4.5\x00\x00")
	})
	if f.Factors["capability"] != 70 {
		t.Fatalf("capability with ILC banner: got %d want 70", f.Factors["capability"])
	}
}

func TestProbeBannerProConOS(t *testing.T) {
	t.Parallel()
	// PCWorx + ProConOS share the KW-Software runtime in many
	// ILC firmwares — the marker still positively identifies
	// PCWorx-speaking servers on the runtime port.
	f := probeAgainstResponder(t, func() []byte {
		return []byte("\xFF\xFE\xAB\xCDProConOS V5.0.0.40 GeneralFirmware")
	})
	if f.Factors["capability"] != 70 {
		t.Fatalf("capability with ProConOS banner: got %d want 70", f.Factors["capability"])
	}
}

func TestProbeSilentResponder(t *testing.T) {
	t.Parallel()
	f := probeAgainstResponder(t, func() []byte { return nil })
	if f.Factors["capability"] != 30 {
		t.Fatalf("capability: got %d want 30 (no reply)", f.Factors["capability"])
	}
}

func TestProbeNonPCWorx(t *testing.T) {
	t.Parallel()
	f := probeAgainstResponder(t, func() []byte {
		return []byte("HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n")
	})
	if f.Factors["capability"] != 30 {
		t.Fatalf("capability: got %d want 30 (non-PCWorx)", f.Factors["capability"])
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
