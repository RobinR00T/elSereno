package finsudp

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"local/elsereno/internal/core"
	"local/elsereno/internal/protocols/finsudp/wire"
)

func TestMetadata(t *testing.T) {
	t.Parallel()
	m := Default().Metadata()
	if m.Name != Name {
		t.Fatalf("Name: got %q", m.Name)
	}
	if m.DefaultPort != 9600 {
		t.Fatalf("DefaultPort: got %d", m.DefaultPort)
	}
	if m.Build != "default" {
		t.Fatalf("Build: got %q", m.Build)
	}
	if !strings.Contains(m.Description, "FINS") {
		t.Fatalf("Description should mention FINS: %q", m.Description)
	}
}

func TestClassifyParseError(t *testing.T) {
	t.Parallel()
	cases := []struct {
		err  error
		want string
	}{
		{wire.ErrShortFrame, "short FINS frame"},
		{wire.ErrServiceMismatch, "SID echo mismatch"},
		{wire.ErrEndCodeNonZero, "end-code non-zero"},
		{wire.ErrNotResponse, "not a response"},
		{errors.New("anything else"), "parse failure"},
	}
	for _, c := range cases {
		got := classifyParseError(c.err, 42)
		if !strings.Contains(got, c.want) {
			t.Fatalf("classifyParseError(%v) = %q want substring %q", c.err, got, c.want)
		}
	}
}

func TestSanitizeModelStripsControl(t *testing.T) {
	t.Parallel()
	in := "CJ2M-CPU\x00\x1b[31m33\n"
	got := sanitizeModel(in)
	if got != "CJ2M-CPU[31m33" {
		t.Fatalf("sanitizeModel: got %q", got)
	}
}

func TestSanitizeModelKeepsPrintable(t *testing.T) {
	t.Parallel()
	in := "NJ501-1500"
	if got := sanitizeModel(in); got != in {
		t.Fatalf("sanitizeModel preserved printable bytes incorrectly: got %q", got)
	}
}

func TestBuildFindingFactors(t *testing.T) {
	t.Parallel()
	target := core.Target{
		Address: netip.MustParseAddr("203.0.113.7"),
		Port:    9600,
	}
	cdYes := buildFinding(target, "FINS model=CJ2M-CPU33", true)
	cdNo := buildFinding(target, "no reply", false)
	if cdYes.Factors["capability"] <= cdNo.Factors["capability"] {
		t.Fatalf("capability should jump when FINS responds: yes=%d no=%d",
			cdYes.Factors["capability"], cdNo.Factors["capability"])
	}
	if cdYes.Score == 0 {
		t.Fatalf("score should be non-zero")
	}
	if cdYes.Protocol != Name {
		t.Fatalf("Protocol: got %q", cdYes.Protocol)
	}
}

// probeAgainstResponder dials a fake FINS responder, drives the real
// Probe path, and returns the Finding.
func probeAgainstResponder(t *testing.T, respond func(req []byte) []byte) *core.Finding {
	t.Helper()
	listenerCtx, listenerCancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(listenerCancel)
	lc := &net.ListenConfig{}
	pc, err := lc.ListenPacket(listenerCtx, "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		n, src, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		reply := respond(buf[:n])
		if reply != nil {
			_, _ = pc.WriteTo(reply, src)
		}
	}()
	addr, ok := pc.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("LocalAddr type: got %T", pc.LocalAddr())
	}
	if addr.Port < 0 || addr.Port > 0xFFFF {
		t.Fatalf("ephemeral port out of uint16 range: %d", addr.Port)
	}
	target := core.Target{
		Address: addr.AddrPort().Addr(),
		Port:    core.Port(uint16(addr.Port)), // #nosec G115 -- guarded above; addr.Port is a kernel-assigned ephemeral.
	}
	plugin := &Plugin{DialTimeout: 500 * time.Millisecond, IOTimeout: 500 * time.Millisecond}
	probeCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)
	f, err := plugin.Probe(probeCtx, target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	return f
}

func TestProbeAgainstHappyPath(t *testing.T) {
	t.Parallel()
	f := probeAgainstResponder(t, func(req []byte) []byte {
		if len(req) < 11 {
			return nil
		}
		sid := req[9]
		// Build a response frame: response ICF + SID echo +
		// MRC/SRC + zero end code + 60-byte controller data.
		resp := []byte{
			0xC0, 0x00, 0x02, // ICF / RSV / GCT — response bit set
			0x00, 0x01, 0x00,
			0x00, 0x00, 0x00,
			sid,
			0x05, 0x01, // MRC / SRC
			0x00, 0x00, // end code: success
		}
		// 20-byte model "NJ501-1500", padded with 0x20.
		resp = append(resp, padTo20("NJ501-1500")...)
		// 20-byte internal code.
		resp = append(resp, padTo20("V1.10")...)
		// 20-byte system version.
		resp = append(resp, padTo20("1.10 SYS")...)
		return resp
	})
	if f.Factors["capability"] != 75 {
		t.Fatalf("capability factor: got %d want 75", f.Factors["capability"])
	}
	if f.Protocol != Name {
		t.Fatalf("Protocol: got %q", f.Protocol)
	}
}

func TestProbeAgainstSilentResponder(t *testing.T) {
	t.Parallel()
	f := probeAgainstResponder(t, func(_ []byte) []byte { return nil })
	if f.Factors["capability"] != 30 {
		t.Fatalf("capability factor: got %d want 30 (no reply)", f.Factors["capability"])
	}
}

func TestProbeAgainstNonFINSResponder(t *testing.T) {
	t.Parallel()
	f := probeAgainstResponder(t, func(_ []byte) []byte {
		// 4-byte garbage; not a FINS frame.
		return []byte{0xDE, 0xAD, 0xBE, 0xEF}
	})
	if f.Factors["capability"] != 30 {
		t.Fatalf("capability factor: got %d want 30 (non-FINS)", f.Factors["capability"])
	}
}

func TestProbeAgainstRefusalEndCode(t *testing.T) {
	t.Parallel()
	f := probeAgainstResponder(t, func(req []byte) []byte {
		if len(req) < 11 {
			return nil
		}
		sid := req[9]
		// 14-byte response with non-zero end code.
		return []byte{
			0xC0, 0x00, 0x02,
			0x00, 0x01, 0x00,
			0x00, 0x00, 0x00,
			sid,
			0x05, 0x01,
			0x01, 0x01, // end code: refusal
		}
	})
	if f.Factors["capability"] != 30 {
		t.Fatalf("capability factor: got %d want 30 (refusal)", f.Factors["capability"])
	}
}

func TestProxyHandlerFailClosed(t *testing.T) {
	t.Parallel()
	h := Default().ProxyHandler()
	err := h.Handle(context.Background(), nil, nil)
	if err == nil {
		t.Fatal("ProxyHandler should refuse")
	}
	if !strings.Contains(err.Error(), "UDP") {
		t.Fatalf("error should mention UDP: %v", err)
	}
}

func TestREPLStub(t *testing.T) {
	t.Parallel()
	err := Default().REPL(context.Background(), nil)
	if err == nil {
		t.Fatal("REPL stub should return an error")
	}
}

func TestNewSIDRetriesUntilNonZero(t *testing.T) {
	t.Parallel()
	for i := 0; i < 32; i++ {
		sid, err := newSID()
		if err != nil {
			t.Fatalf("newSID: %v", err)
		}
		if sid == 0 {
			t.Fatalf("newSID returned zero on iter %d", i)
		}
	}
}

// padTo20 right-pads s with 0x20 to exactly 20 bytes (the FINS
// CONTROLLER DATA READ field width).
func padTo20(s string) []byte {
	b := make([]byte, 20)
	copy(b, s)
	for i := len(s); i < 20; i++ {
		b[i] = 0x20
	}
	return b
}
