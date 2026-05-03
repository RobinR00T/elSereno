package mms

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"local/elsereno/internal/core"
	"local/elsereno/internal/protocols/mms/wire"
)

func TestMetadata(t *testing.T) {
	t.Parallel()
	m := Default().Metadata()
	if m.Name != Name {
		t.Fatalf("Name: got %q", m.Name)
	}
	if m.DefaultPort != 102 {
		t.Fatalf("DefaultPort: got %d want 102", m.DefaultPort)
	}
	if !strings.Contains(strings.ToLower(m.Description), "mms") {
		t.Fatalf("Description should mention MMS: %q", m.Description)
	}
	if !strings.Contains(strings.ToLower(m.Description), "61850") {
		t.Fatalf("Description should reference IEC 61850: %q", m.Description)
	}
}

func TestClassifyParseError(t *testing.T) {
	t.Parallel()
	cases := []struct {
		err  error
		want string
	}{
		{wire.ErrShortCOTP, "short MMS"},
		{wire.ErrNotCOTPConfirm, "DR (likely S7"},
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
		Address: netip.MustParseAddr("198.51.100.42"),
		Port:    102,
	}
	yes := buildFinding(target, "MMS COTP confirm", true)
	no := buildFinding(target, "MMS COTP got DR (likely S7)", false)
	if yes.Factors["capability"] <= no.Factors["capability"] {
		t.Fatalf("capability should jump on MMS confirm: yes=%d no=%d",
			yes.Factors["capability"], no.Factors["capability"])
	}
	if yes.Factors["cve_exposure"] != 9 {
		t.Fatalf("cve_exposure: got %d want 9 (CVE-2018-13802 / 2020-7517 / 2021-22779 / 2022-3008 / 2023-39435)", yes.Factors["cve_exposure"])
	}
	if yes.Factors["impact_class"] != 85 {
		t.Fatalf("impact_class: got %d want 85 (grid-scale)", yes.Factors["impact_class"])
	}
}

// probeAgainstResponder spins up a 127.0.0.1 listener that
// reads the TPKT envelope (4 header + N payload) and replies
// with whatever respond() returns. respond is given the
// inbound payload so the test can verify the inbound CR was
// the MMS variant.
func probeAgainstResponder(t *testing.T, respond func(inbound []byte) []byte) *core.Finding {
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
		hdr := make([]byte, 4)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return
		}
		length := int(hdr[2])<<8 | int(hdr[3])
		if length < 4 {
			return
		}
		body := make([]byte, length-4)
		if _, err := io.ReadFull(conn, body); err != nil {
			return
		}
		if reply := respond(body); reply != nil {
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

// buildTPKT helper for the responder side.
func buildTPKT(payload []byte) []byte {
	total := 4 + len(payload)
	out := []byte{0x03, 0x00, byte(total >> 8), byte(total & 0xff)} // #nosec G115 -- payload bounded by tests
	return append(out, payload...)
}

func TestProbeMMSConfirm(t *testing.T) {
	t.Parallel()
	f := probeAgainstResponder(t, func(inbound []byte) []byte {
		// The inbound payload should carry the MMS-style TSAP
		// pattern (`C1 02 00 01` + `C2 02 00 01`).
		if !bytes.Contains(inbound, []byte{0xC1, 0x02, 0x00, 0x01}) {
			t.Errorf("inbound CR missing MMS source TSAP: % x", inbound)
		}
		// Reply with COTP-CC.
		cc := []byte{0x06, 0xD0, 0x00, 0x01, 0x00, 0x01, 0x00}
		return buildTPKT(cc)
	})
	if f.Factors["capability"] != 75 {
		t.Fatalf("capability on MMS confirm: got %d want 75", f.Factors["capability"])
	}
}

func TestProbeS7Disconnect(t *testing.T) {
	t.Parallel()
	f := probeAgainstResponder(t, func(_ []byte) []byte {
		// COTP-DR — what S7 returns when our MMS TSAPs don't match.
		dr := []byte{0x06, 0x80, 0x00, 0x01, 0x00, 0x01, 0x01}
		return buildTPKT(dr)
	})
	if f.Factors["capability"] != 30 {
		t.Fatalf("capability on COTP-DR: got %d want 30 (likely S7, not MMS)", f.Factors["capability"])
	}
}

func TestProbeNonTPKT(t *testing.T) {
	t.Parallel()
	f := probeAgainstResponder(t, func(_ []byte) []byte {
		return []byte("HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n")
	})
	if f.Factors["capability"] != 30 {
		t.Fatalf("capability on non-TPKT reply: got %d want 30", f.Factors["capability"])
	}
}

func TestProbeSilentClose(t *testing.T) {
	t.Parallel()
	f := probeAgainstResponder(t, func(_ []byte) []byte { return nil })
	if f.Factors["capability"] != 30 {
		t.Fatalf("capability on silent close: got %d want 30", f.Factors["capability"])
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
