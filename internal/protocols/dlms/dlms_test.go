package dlms

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
	"local/elsereno/internal/protocols/dlms/wire"
)

func TestMetadata(t *testing.T) {
	t.Parallel()
	m := Default().Metadata()
	if m.Name != Name {
		t.Fatalf("Name: got %q", m.Name)
	}
	if m.DefaultPort != 4059 {
		t.Fatalf("DefaultPort: got %d", m.DefaultPort)
	}
	if !strings.Contains(m.Description, "DLMS") {
		t.Fatalf("Description should mention DLMS: %q", m.Description)
	}
}

func TestClassifyParseError(t *testing.T) {
	t.Parallel()
	cases := []struct {
		err  error
		want string
	}{
		{wire.ErrShortFrame, "short DLMS"},
		{wire.ErrBadWrapperVersion, "wrapper version not 0x0001"},
		{wire.ErrLengthMismatch, "wrapper length disagreement"},
		{wire.ErrNotAARE, "APDU not AARE"},
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
		Port:    4059,
	}
	yes := buildFinding(target, "DLMS AARE", true)
	no := buildFinding(target, "no usable reply", false)
	if yes.Factors["capability"] <= no.Factors["capability"] {
		t.Fatalf("capability should jump on DLMS reply: yes=%d no=%d",
			yes.Factors["capability"], no.Factors["capability"])
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
		buf := make([]byte, 37)
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

func TestProbeHappyPath(t *testing.T) {
	t.Parallel()
	f := probeAgainstResponder(t, buildAARE)
	if f.Factors["capability"] != 70 {
		t.Fatalf("capability factor: got %d want 70", f.Factors["capability"])
	}
}

func TestProbeWrapperOnlyStillCounts(t *testing.T) {
	t.Parallel()
	// Wrapper-shaped but APDU is not AARE.
	f := probeAgainstResponder(t, func() []byte {
		resp := make([]byte, 12)
		binary.BigEndian.PutUint16(resp[0:2], 0x0001)
		binary.BigEndian.PutUint16(resp[2:4], 0x0001)
		binary.BigEndian.PutUint16(resp[4:6], 0x0010)
		binary.BigEndian.PutUint16(resp[6:8], 4)
		resp[8] = 0x60 // AARQ tag, not AARE
		return resp
	})
	if f.Factors["capability"] != 70 {
		t.Fatalf("capability factor: got %d want 70 (wrapper-only counts)", f.Factors["capability"])
	}
}

func TestProbeSilentResponder(t *testing.T) {
	t.Parallel()
	f := probeAgainstResponder(t, func() []byte { return nil })
	if f.Factors["capability"] != 30 {
		t.Fatalf("capability factor: got %d want 30 (no reply)", f.Factors["capability"])
	}
}

func TestProbeNonDLMS(t *testing.T) {
	t.Parallel()
	f := probeAgainstResponder(t, func() []byte {
		resp := make([]byte, 12)
		binary.BigEndian.PutUint16(resp[0:2], 0xDEAD) // wrong wrapper version
		return resp
	})
	if f.Factors["capability"] != 30 {
		t.Fatalf("capability factor: got %d want 30 (non-DLMS)", f.Factors["capability"])
	}
}

func TestProxyHandlerRefuses(t *testing.T) {
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
		_, _ = clientW.Write(wire.BuildAARQ())
		_ = clientW.Close()
	}()
	rw := readWritePair{r: clientR, w: respW}
	upstream := readWritePair{r: upstreamR, w: io.Discard}
	handler := Default().ProxyHandler()
	respDone := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 16)
		n, _ := io.ReadFull(respR, buf)
		respDone <- buf[:n]
	}()
	if err := handler.Handle(context.Background(), rw, upstream); err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("Handle: %v", err)
	}
	resp := <-respDone
	if len(resp) != 16 {
		t.Fatalf("response length: got %d want 16", len(resp))
	}
	if binary.BigEndian.Uint16(resp[0:2]) != 0x0001 {
		t.Fatalf("wrapper version: got 0x%04x", binary.BigEndian.Uint16(resp[0:2]))
	}
	if resp[8] != 0x61 {
		t.Fatalf("AARE tag: got 0x%02x", resp[8])
	}
}

func TestREPLStub(t *testing.T) {
	t.Parallel()
	if err := Default().REPL(context.Background(), nil); err == nil {
		t.Fatal("REPL stub should return an error")
	}
}

// buildAARE returns a 28-byte AARE frame: 8 wrapper + 20 APDU.
func buildAARE() []byte {
	const apduLen = 20
	frame := make([]byte, 8+apduLen)
	binary.BigEndian.PutUint16(frame[0:2], 0x0001)
	binary.BigEndian.PutUint16(frame[2:4], 0x0001)
	binary.BigEndian.PutUint16(frame[4:6], 0x0010)
	binary.BigEndian.PutUint16(frame[6:8], apduLen)
	frame[8] = 0x61
	return frame
}

type readWritePair struct {
	r io.Reader
	w io.Writer
}

func (rw readWritePair) Read(b []byte) (int, error)  { return rw.r.Read(b) }
func (rw readWritePair) Write(b []byte) (int, error) { return rw.w.Write(b) }
