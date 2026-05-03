package slmp

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"local/elsereno/internal/core"
	"local/elsereno/internal/protocols/slmp/wire"
)

func TestMetadata(t *testing.T) {
	t.Parallel()
	m := Default().Metadata()
	if m.Name != Name {
		t.Fatalf("Name: got %q", m.Name)
	}
	if m.DefaultPort != 5007 {
		t.Fatalf("DefaultPort: got %d", m.DefaultPort)
	}
	if m.Build != "default" {
		t.Fatalf("Build: got %q", m.Build)
	}
	if !strings.Contains(m.Description, "SLMP") {
		t.Fatalf("Description should mention SLMP: %q", m.Description)
	}
}

func TestClassifyParseError(t *testing.T) {
	t.Parallel()
	cases := []struct {
		err  error
		want string
	}{
		{wire.ErrShortFrame, "short SLMP"},
		{wire.ErrLengthMismatch, "length-field mismatch"},
		{wire.ErrEndCodeNonZero, "end-code non-zero"},
		{wire.ErrNotResponse, "not a response"},
		{errors.New("anything else"), "parse failure"},
	}
	for _, c := range cases {
		got := classifyParseError(c.err)
		if !strings.Contains(got, c.want) {
			t.Fatalf("classifyParseError(%v) = %q want substring %q", c.err, got, c.want)
		}
	}
}

func TestSanitizeModelStripsControl(t *testing.T) {
	t.Parallel()
	in := "Q03UDV\x00\x1b[1mCPU\n"
	got := sanitizeModel(in)
	if got != "Q03UDV[1mCPU" {
		t.Fatalf("sanitizeModel: got %q", got)
	}
}

func TestSanitizeModelKeepsPrintable(t *testing.T) {
	t.Parallel()
	in := "L26CPU-BT"
	if got := sanitizeModel(in); got != in {
		t.Fatalf("sanitizeModel preserved printable bytes incorrectly: got %q", got)
	}
}

func TestBuildFindingFactors(t *testing.T) {
	t.Parallel()
	target := core.Target{
		Address: netip.MustParseAddr("203.0.113.7"),
		Port:    5007,
	}
	cdYes := buildFinding(target, "SLMP model=Q03UDVCPU type=0x4612", true)
	cdNo := buildFinding(target, "no usable reply", false)
	if cdYes.Factors["capability"] <= cdNo.Factors["capability"] {
		t.Fatalf("capability should jump when SLMP responds: yes=%d no=%d",
			cdYes.Factors["capability"], cdNo.Factors["capability"])
	}
	if cdYes.Score == 0 {
		t.Fatalf("score should be non-zero")
	}
	if cdYes.Protocol != Name {
		t.Fatalf("Protocol: got %q", cdYes.Protocol)
	}
}

// probeAgainstResponder dials a fake SLMP responder, drives the
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
		// Drain the 15-byte READ CPU MODEL NAME request.
		buf := make([]byte, 15)
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
		return buildSuccessResp("Q03UDVCPU", 0x4612)
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
	f := probeAgainstResponder(t, func() []byte { return nil })
	if f.Factors["capability"] != 30 {
		t.Fatalf("capability factor: got %d want 30 (no reply)", f.Factors["capability"])
	}
}

func TestProbeAgainstNonSLMPResponder(t *testing.T) {
	t.Parallel()
	f := probeAgainstResponder(t, func() []byte {
		// 11 bytes of garbage; passes the length floor but fails
		// the subheader.
		return []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	})
	if f.Factors["capability"] != 30 {
		t.Fatalf("capability factor: got %d want 30 (non-SLMP)", f.Factors["capability"])
	}
}

func TestProbeAgainstRefusalEndCode(t *testing.T) {
	t.Parallel()
	f := probeAgainstResponder(t, func() []byte {
		// Error frame: declared length 2 (just end code).
		return []byte{
			0xD0, 0x00,
			0x00, 0xFF,
			0xFF, 0x03,
			0x00,
			0x02, 0x00, // declared length 2
			0x59, 0xC0, // end code 0xC059
		}
	})
	if f.Factors["capability"] != 30 {
		t.Fatalf("capability factor: got %d want 30 (refusal)", f.Factors["capability"])
	}
}

func TestProbeAgainstAbsurdLength(t *testing.T) {
	t.Parallel()
	f := probeAgainstResponder(t, func() []byte {
		// Header with declared length 0xFFFF — past the
		// MaxResponseDataLength sanity ceiling.
		return []byte{
			0xD0, 0x00,
			0x00, 0xFF,
			0xFF, 0x03,
			0x00,
			0xFF, 0xFF, // declared length 65535
			0x00, 0x00,
		}
	})
	if f.Factors["capability"] != 30 {
		t.Fatalf("capability factor: got %d want 30 (absurd length)", f.Factors["capability"])
	}
}

func TestProxyHandlerRefusesEveryRequest(t *testing.T) {
	t.Parallel()
	// Pipe a request and read the refusal response.
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
		_, _ = clientW.Write(wire.BuildReadCPUModelName())
		_ = clientW.Close()
	}()
	rw := readWritePair{r: clientR, w: respW}
	upstream := readWritePair{r: upstreamR, w: io.Discard}
	handler := Default().ProxyHandler()

	respDone := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 11)
		n, _ := io.ReadFull(respR, buf)
		respDone <- buf[:n]
	}()

	if err := handler.Handle(context.Background(), rw, upstream); err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("Handle: %v", err)
	}

	resp := <-respDone
	if len(resp) != 11 {
		t.Fatalf("response length: got %d want 11", len(resp))
	}
	if binary.LittleEndian.Uint16(resp[0:2]) != 0x00D0 {
		t.Fatalf("subheader: got 0x%04x want 0x00D0", binary.LittleEndian.Uint16(resp[0:2]))
	}
	if binary.LittleEndian.Uint16(resp[9:11]) != 0xC059 {
		t.Fatalf("end code: got 0x%04x want 0xC059", binary.LittleEndian.Uint16(resp[9:11]))
	}
}

func TestREPLStub(t *testing.T) {
	t.Parallel()
	err := Default().REPL(context.Background(), nil)
	if err == nil {
		t.Fatal("REPL stub should return an error")
	}
}

// buildSuccessResp returns a 29-byte SLMP success response
// carrying the given model name (right-padded to 16 bytes) and
// CPU type code.
func buildSuccessResp(model string, cpuType uint16) []byte {
	frame := make([]byte, 29)
	binary.LittleEndian.PutUint16(frame[0:2], 0x00D0)
	frame[2] = 0x00
	frame[3] = 0xFF
	binary.LittleEndian.PutUint16(frame[4:6], 0x03FF)
	frame[6] = 0x00
	binary.LittleEndian.PutUint16(frame[7:9], 0x0014) // declared length 20
	binary.LittleEndian.PutUint16(frame[9:11], 0x0000)
	copy(frame[11:27], padTo16(model))
	binary.LittleEndian.PutUint16(frame[27:29], cpuType)
	return frame
}

func padTo16(s string) []byte {
	b := make([]byte, 16)
	copy(b, s)
	for i := len(s); i < 16; i++ {
		b[i] = 0x20
	}
	return b
}

// readWritePair adapts two halves of an io.Pipe pair into the
// io.ReadWriter that ProxyHandler.Handle expects.
type readWritePair struct {
	r io.Reader
	w io.Writer
}

func (rw readWritePair) Read(b []byte) (int, error)  { return rw.r.Read(b) }
func (rw readWritePair) Write(b []byte) (int, error) { return rw.w.Write(b) }
