package mbustcp

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
	"local/elsereno/internal/protocols/mbustcp/wire"
)

func TestMetadata(t *testing.T) {
	t.Parallel()
	m := Default().Metadata()
	if m.Name != Name {
		t.Fatalf("Name: got %q", m.Name)
	}
	if m.DefaultPort != 10001 {
		t.Fatalf("DefaultPort: got %d", m.DefaultPort)
	}
	if !strings.Contains(m.Description, "M-Bus") {
		t.Fatalf("Description should mention M-Bus: %q", m.Description)
	}
}

func TestClassifyParseError(t *testing.T) {
	t.Parallel()
	cases := []struct {
		err  error
		want string
	}{
		{wire.ErrShortFrame, "short M-Bus"},
		{wire.ErrBadStart, "start byte not 0x68"},
		{wire.ErrLengthMismatch, "length-field disagreement"},
		{wire.ErrBadStop, "stop byte not 0x16"},
		{wire.ErrChecksumMismatch, "checksum mismatch"},
		{wire.ErrNotVarDataResponse, "CI not 0x72"},
		{errors.New("anything else"), "parse failure"},
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
		Port:    10001,
	}
	yes := buildFinding(target, "M-Bus manuf=ABB medium=0x07 ver=0x01", true)
	no := buildFinding(target, "no usable reply", false)
	if yes.Factors["capability"] <= no.Factors["capability"] {
		t.Fatalf("capability should jump on M-Bus reply: yes=%d no=%d",
			yes.Factors["capability"], no.Factors["capability"])
	}
}

// probeAgainstResponder dials a fake M-Bus TCP responder.
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
		buf := make([]byte, 5)
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
		t.Fatalf("ephemeral port out of range: %d", addr.Port)
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
	f := probeAgainstResponder(t, func() []byte {
		return buildRSPUD(0x12345678, "KAM", 0x12, 0x07)
	})
	if f.Factors["capability"] != 70 {
		t.Fatalf("capability factor: got %d want 70", f.Factors["capability"])
	}
}

func TestProbeACK(t *testing.T) {
	t.Parallel()
	f := probeAgainstResponder(t, func() []byte {
		return []byte{0xE5}
	})
	if f.Factors["capability"] != 70 {
		t.Fatalf("capability factor: got %d want 70 (ACK only)", f.Factors["capability"])
	}
}

func TestProbeSilentResponder(t *testing.T) {
	t.Parallel()
	f := probeAgainstResponder(t, func() []byte { return nil })
	if f.Factors["capability"] != 30 {
		t.Fatalf("capability factor: got %d want 30 (no reply)", f.Factors["capability"])
	}
}

func TestProbeNonMBus(t *testing.T) {
	t.Parallel()
	f := probeAgainstResponder(t, func() []byte {
		return []byte{0xDE, 0xAD, 0xBE, 0xEF}
	})
	if f.Factors["capability"] != 30 {
		t.Fatalf("capability factor: got %d want 30 (non-M-Bus)", f.Factors["capability"])
	}
}

func TestProxyHandlerACK(t *testing.T) {
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
		_, _ = clientW.Write(wire.BuildREQUD2(0x01))
		_ = clientW.Close()
	}()
	rw := readWritePair{r: clientR, w: respW}
	upstream := readWritePair{r: upstreamR, w: io.Discard}
	handler := Default().ProxyHandler()
	respDone := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 1)
		n, _ := io.ReadFull(respR, buf)
		respDone <- buf[:n]
	}()
	if err := handler.Handle(context.Background(), rw, upstream); err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("Handle: %v", err)
	}
	resp := <-respDone
	if len(resp) != 1 || resp[0] != 0xE5 {
		t.Fatalf("response: got %x want [0xE5]", resp)
	}
}

func TestREPLStub(t *testing.T) {
	t.Parallel()
	if err := Default().REPL(context.Background(), nil); err == nil {
		t.Fatal("REPL stub should return an error")
	}
}

// buildRSPUD produces an RSP_UD long frame for the test harness.
// The shift+truncate byte extractions below are the canonical
// Go idiom for wire-frame synthesis (gosec G115 noise).
//
// #nosec G115 -- false positives on byte extractions.
func buildRSPUD(id uint32, manuf string, version, medium byte) []byte {
	if len(manuf) != 3 {
		panic("buildRSPUD: manuf must be 3 letters")
	}
	manufID := uint16(0)
	manufID |= uint16(manuf[0]-'A'+1) << 10
	manufID |= uint16(manuf[1]-'A'+1) << 5
	manufID |= uint16(manuf[2] - 'A' + 1)
	body := []byte{
		0x08, 0x01, 0x72,
		byte(id), byte(id >> 8), byte(id >> 16), byte(id >> 24),
		byte(manufID), byte(manufID >> 8),
		version, medium,
		0x00, 0x00,
		0x00, 0x00,
	}
	declaredLen := byte(len(body))
	frame := []byte{0x68, declaredLen, declaredLen, 0x68}
	frame = append(frame, body...)
	var cs byte
	for _, b := range body {
		cs += b
	}
	frame = append(frame, cs, 0x16)
	return frame
}

type readWritePair struct {
	r io.Reader
	w io.Writer
}

func (rw readWritePair) Read(b []byte) (int, error)  { return rw.r.Read(b) }
func (rw readWritePair) Write(b []byte) (int, error) { return rw.w.Write(b) }
