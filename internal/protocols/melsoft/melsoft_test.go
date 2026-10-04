package melsoft

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"local/elsereno/internal/core"
	"local/elsereno/internal/protocols/melsoft/wire"
)

func TestMetadata(t *testing.T) {
	t.Parallel()
	m := Default().Metadata()
	if m.Name != Name {
		t.Fatalf("Name: got %q", m.Name)
	}
	if m.DefaultPort != 5007 {
		t.Fatalf("DefaultPort: got %d want 5007", m.DefaultPort)
	}
	if !strings.Contains(m.Description, "MELSOFT") {
		t.Fatalf("Description should mention MELSOFT: %q", m.Description)
	}
}

func TestClassifyParseError(t *testing.T) {
	t.Parallel()
	cases := []struct {
		err  error
		want string
	}{
		{wire.ErrShortFrame, "short MELSOFT"},
		{wire.ErrNotResponse, "marker (0xD7) absent"},
		{errors.New("other"), "parse failure"},
	}
	for _, c := range cases {
		if got := classifyParseError(c.err); !strings.Contains(got, c.want) {
			t.Fatalf("classifyParseError(%v) = %q want substring %q", c.err, got, c.want)
		}
	}
}

func TestBuildFindingFactors(t *testing.T) {
	t.Parallel()
	target := core.Target{Address: netip.MustParseAddr("203.0.113.7"), Port: 5007}
	yes := buildFinding(target, "MELSOFT model=Q03UDECPU", true, "Q03UDECPU")
	no := buildFinding(target, "no usable reply", false, "")
	if yes.Factors["capability"] <= no.Factors["capability"] {
		t.Fatalf("capability should jump on a MELSOFT reply: yes=%d no=%d",
			yes.Factors["capability"], no.Factors["capability"])
	}
	// CVE enrichment: an iQ-F (FX5) model lifts cve_exposure above the
	// classic-Q baseline via cve.ForSLMP.
	iqf := buildFinding(target, "MELSOFT model=FX5U-32MT/ES", true, "FX5U-32MT/ES")
	if iqf.Factors["cve_exposure"] <= yes.Factors["cve_exposure"] {
		t.Fatalf("iQ-F cve_exposure should exceed the classic-Q baseline: iQ-F=%d Q=%d",
			iqf.Factors["cve_exposure"], yes.Factors["cve_exposure"])
	}
}

func probeAgainstResponder(t *testing.T, respond func() []byte) *core.Finding {
	t.Helper()
	lc := &net.ListenConfig{}
	lctx, lcancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(lcancel)
	ln, err := lc.Listen(lctx, "tcp", "127.0.0.1:0")
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
		// Drain the fixed-size request, then reply (or not) and close.
		_, _ = io.ReadFull(conn, make([]byte, len(wire.GetCPUInfoRequest)))
		if reply := respond(); reply != nil {
			_, _ = conn.Write(reply)
		}
	}()
	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("Addr type: got %T", ln.Addr())
	}
	if addr.Port < 0 || addr.Port > 0xFFFF {
		t.Fatalf("port out of range: %d", addr.Port)
	}
	target := core.Target{
		Address: addr.AddrPort().Addr(),
		Port:    core.Port(uint16(addr.Port)), // #nosec G115 -- guarded.
	}
	plugin := &Plugin{DialTimeout: 1 * time.Second, IOTimeout: 1 * time.Second}
	pctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	f, err := plugin.Probe(pctx, target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	return f
}

func TestProbeRealModelEcho(t *testing.T) {
	t.Parallel()
	resp, err := hex.DecodeString("d700c80000111107000000e40300ffff03000038009c000c08000000001004000000000101010000005130335544454350552020202020202068020008baba081020210316002002000101e802")
	if err != nil {
		t.Fatal(err)
	}
	f := probeAgainstResponder(t, func() []byte { return resp })
	if f.Factors["capability"] != 75 {
		t.Fatalf("capability: got %d want 75", f.Factors["capability"])
	}
}

func TestProbeSilentResponder(t *testing.T) {
	t.Parallel()
	f := probeAgainstResponder(t, func() []byte { return nil })
	if f.Factors["capability"] != 30 {
		t.Fatalf("capability: got %d want 30 (no reply)", f.Factors["capability"])
	}
}

func TestProbeNonMelsoft(t *testing.T) {
	t.Parallel()
	f := probeAgainstResponder(t, func() []byte {
		return []byte("HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n")
	})
	if f.Factors["capability"] != 30 {
		t.Fatalf("capability: got %d want 30 (non-MELSOFT)", f.Factors["capability"])
	}
}

func TestProxyHandlerFailClosed(t *testing.T) {
	t.Parallel()
	err := Default().ProxyHandler().Handle(context.Background(), nil, nil)
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
