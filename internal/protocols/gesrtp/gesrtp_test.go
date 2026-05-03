package gesrtp

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
	"local/elsereno/internal/protocols/gesrtp/wire"
)

func TestMetadata(t *testing.T) {
	t.Parallel()
	m := Default().Metadata()
	if m.Name != Name {
		t.Fatalf("Name: got %q", m.Name)
	}
	if m.DefaultPort != 18245 {
		t.Fatalf("DefaultPort: got %d", m.DefaultPort)
	}
	if m.Build != "default" {
		t.Fatalf("Build: got %q", m.Build)
	}
	if !strings.Contains(m.Description, "SRTP") {
		t.Fatalf("Description should mention SRTP: %q", m.Description)
	}
}

func TestClassifyParseError(t *testing.T) {
	t.Parallel()
	cases := []struct {
		err  error
		n    int
		want string
	}{
		{wire.ErrShortFrame, 12, "short SRTP frame (12 bytes)"},
		{wire.ErrNotResponse, 56, "SRTP response type byte not 0x03"},
		{errors.New("anything else"), 0, "parse failure"},
	}
	for _, c := range cases {
		got := classifyParseError(c.err, c.n)
		if !strings.Contains(got, c.want) {
			t.Fatalf("classifyParseError(%v, %d) = %q want substring %q",
				c.err, c.n, got, c.want)
		}
	}
}

func TestBuildFindingFactors(t *testing.T) {
	t.Parallel()
	target := core.Target{
		Address: netip.MustParseAddr("203.0.113.7"),
		Port:    18245,
	}
	cdYes := buildFinding(target, "SRTP mailbox response", true, "")
	cdNo := buildFinding(target, "no usable reply", false, "")
	cdHint := buildFinding(target, "SRTP model=IC693CPU374", true, "IC693CPU374")
	if cdYes.Factors["capability"] <= cdNo.Factors["capability"] {
		t.Fatalf("capability should jump when SRTP responds: yes=%d no=%d",
			cdYes.Factors["capability"], cdNo.Factors["capability"])
	}
	if cdHint.Factors["capability"] <= cdYes.Factors["capability"] {
		t.Fatalf("capability should jump again when a model hint is extracted: hint=%d yes=%d",
			cdHint.Factors["capability"], cdYes.Factors["capability"])
	}
	if cdHint.Factors["capability"] != 75 {
		t.Fatalf("hint capability: got %d want 75", cdHint.Factors["capability"])
	}
	if cdYes.Score == 0 {
		t.Fatalf("score should be non-zero")
	}
	if cdYes.Protocol != Name {
		t.Fatalf("Protocol: got %q", cdYes.Protocol)
	}
}

func TestProbeWithModelHintLiftsCapability(t *testing.T) {
	t.Parallel()
	f := probeAgainstResponder(t, func() []byte {
		// 56-byte response with byte 0 = 0x03 + an embedded
		// "IC695CPE330" hint at offset 16.
		resp := make([]byte, 56)
		resp[0] = 0x03
		copy(resp[16:], []byte("IC695CPE330"))
		return resp
	})
	if f.Factors["capability"] != 75 {
		t.Fatalf("capability factor with hint: got %d want 75", f.Factors["capability"])
	}
}

// probeAgainstResponder dials a fake SRTP responder, drives the
// real Probe path, and returns the Finding.
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
		// Drain the 56-byte CONNECTION INIT request.
		buf := make([]byte, 56)
		_, _ = io.ReadFull(conn, buf)
		reply := respond()
		if reply != nil {
			_, _ = conn.Write(reply)
		}
	}()
	addr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("Addr type: got %T", listener.Addr())
	}
	if addr.Port < 0 || addr.Port > 0xFFFF {
		t.Fatalf("ephemeral port out of uint16 range: %d", addr.Port)
	}
	target := core.Target{
		Address: addr.AddrPort().Addr(),
		Port:    core.Port(uint16(addr.Port)), // #nosec G115 -- guarded above; ephemeral.
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

func TestProbeAgainstHappyPath(t *testing.T) {
	t.Parallel()
	f := probeAgainstResponder(t, func() []byte {
		resp := make([]byte, 56)
		resp[0] = 0x03
		return resp
	})
	if f.Factors["capability"] != 70 {
		t.Fatalf("capability factor: got %d want 70", f.Factors["capability"])
	}
	if f.Protocol != Name {
		t.Fatalf("Protocol: got %q", f.Protocol)
	}
}

func TestProbeAgainstSilentResponder(t *testing.T) {
	t.Parallel()
	f := probeAgainstResponder(t, func() []byte { return nil })
	if f.Factors["capability"] != 30 {
		t.Fatalf("capability factor: got %d want 30 (no reply)", f.Factors["capability"])
	}
}

func TestProbeAgainstWrongTypeByte(t *testing.T) {
	t.Parallel()
	f := probeAgainstResponder(t, func() []byte {
		// 56 bytes but type byte is 0x02 (request, not response).
		resp := make([]byte, 56)
		resp[0] = 0x02
		return resp
	})
	if f.Factors["capability"] != 30 {
		t.Fatalf("capability factor: got %d want 30 (wrong type)", f.Factors["capability"])
	}
}

func TestProxyHandlerRefusesEveryRequest(t *testing.T) {
	t.Parallel()
	clientR, clientW := io.Pipe()
	respR, respW := io.Pipe()
	upstreamR, _ := io.Pipe()
	defer func() {
		_ = clientR.Close()
		_ = clientW.Close()
		_ = respR.Close()
		_ = respW.Close()
		_ = upstreamR.Close()
	}()

	go func() {
		_, _ = clientW.Write(wire.BuildConnectionInit())
		_ = clientW.Close()
	}()
	rw := readWritePair{r: clientR, w: respW}
	upstream := readWritePair{r: upstreamR, w: io.Discard}
	handler := Default().ProxyHandler()

	respDone := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 56)
		n, _ := io.ReadFull(respR, buf)
		respDone <- buf[:n]
	}()

	if err := handler.Handle(context.Background(), rw, upstream); err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("Handle: %v", err)
	}

	resp := <-respDone
	if len(resp) != 56 {
		t.Fatalf("response length: got %d want 56", len(resp))
	}
	if resp[0] != 0x03 {
		t.Fatalf("type byte: got 0x%02x want 0x03", resp[0])
	}
	if resp[42] != 0x01 {
		t.Fatalf("status byte: got 0x%02x want 0x01", resp[42])
	}
}

func TestREPLStub(t *testing.T) {
	t.Parallel()
	err := Default().REPL(context.Background(), nil)
	if err == nil {
		t.Fatal("REPL stub should return an error")
	}
}

// readWritePair adapts two halves of an io.Pipe pair into the
// io.ReadWriter that ProxyHandler.Handle expects.
type readWritePair struct {
	r io.Reader
	w io.Writer
}

func (rw readWritePair) Read(b []byte) (int, error)  { return rw.r.Read(b) }
func (rw readWritePair) Write(b []byte) (int, error) { return rw.w.Write(b) }
