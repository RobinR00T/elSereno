package knxip

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"local/elsereno/internal/core"
	"local/elsereno/internal/protocols/knxip/wire"
)

func TestMetadata(t *testing.T) {
	t.Parallel()
	m := Default().Metadata()
	if m.Name != Name {
		t.Fatalf("Name: got %q", m.Name)
	}
	if m.DefaultPort != 3671 {
		t.Fatalf("DefaultPort: got %d", m.DefaultPort)
	}
	if !strings.Contains(m.Description, "KNX") {
		t.Fatalf("Description should mention KNX: %q", m.Description)
	}
}

func TestClassifyParseError(t *testing.T) {
	t.Parallel()
	cases := []struct {
		err  error
		n    int
		want string
	}{
		{wire.ErrShortFrame, 12, "short KNX frame (12 bytes)"},
		{wire.ErrBadHeader, 0, "header bytes wrong"},
		{wire.ErrNotResponse, 0, "service-type not 0x0205"},
		{wire.ErrLengthMismatch, 0, "total-length disagreement"},
		{wire.ErrMissingDeviceInfoDIB, 0, "missing device-info DIB"},
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

func TestSanitizeName(t *testing.T) {
	t.Parallel()
	in := "MDT IP\x00\x1b[31m Iface\n"
	if got := sanitizeName(in); got != "MDT IP[31m Iface" {
		t.Fatalf("sanitizeName: got %q", got)
	}
}

func TestBuildFindingFactors(t *testing.T) {
	t.Parallel()
	target := core.Target{
		Address: netip.MustParseAddr("203.0.113.7"),
		Port:    3671,
	}
	cdYes := buildFinding(target, "KNX name=Gira medium=0x02", true)
	cdNo := buildFinding(target, "no reply", false)
	if cdYes.Factors["capability"] <= cdNo.Factors["capability"] {
		t.Fatalf("capability should jump on KNX reply: yes=%d no=%d",
			cdYes.Factors["capability"], cdNo.Factors["capability"])
	}
	if cdYes.Protocol != Name {
		t.Fatalf("Protocol: got %q", cdYes.Protocol)
	}
}

// probeAgainstResponder dials a fake KNXnet/IP responder.
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
		if reply := respond(buf[:n]); reply != nil {
			_, _ = pc.WriteTo(reply, src)
		}
	}()
	addr, ok := pc.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("LocalAddr type: got %T", pc.LocalAddr())
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

func TestProbeAgainstHappyPath(t *testing.T) {
	t.Parallel()
	f := probeAgainstResponder(t, func(_ []byte) []byte {
		return buildResp("MDT IP Interface")
	})
	if f.Factors["capability"] != 75 {
		t.Fatalf("capability factor: got %d want 75", f.Factors["capability"])
	}
}

func TestProbeAgainstSilentResponder(t *testing.T) {
	t.Parallel()
	f := probeAgainstResponder(t, func(_ []byte) []byte { return nil })
	if f.Factors["capability"] != 30 {
		t.Fatalf("capability factor: got %d want 30 (no reply)", f.Factors["capability"])
	}
}

func TestProbeAgainstNonKNXResponder(t *testing.T) {
	t.Parallel()
	f := probeAgainstResponder(t, func(_ []byte) []byte {
		return []byte{0xDE, 0xAD, 0xBE, 0xEF}
	})
	if f.Factors["capability"] != 30 {
		t.Fatalf("capability factor: got %d want 30 (non-KNX)", f.Factors["capability"])
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
	if err := Default().REPL(context.Background(), nil); err == nil {
		t.Fatal("REPL stub should return an error")
	}
}

// buildResp produces a 60-byte DESCRIPTION_RESPONSE with the
// given friendly name (right-padded with NUL to 30 bytes) and
// canonical TP1 device-info DIB fields.
func buildResp(friendlyName string) []byte {
	resp := make([]byte, 60)
	resp[0] = 0x06
	resp[1] = 0x10
	binary.BigEndian.PutUint16(resp[2:4], 0x0205)
	binary.BigEndian.PutUint16(resp[4:6], 60)
	resp[6] = 0x36
	resp[7] = 0x01
	resp[8] = 0x02
	resp[9] = 0x00
	binary.BigEndian.PutUint16(resp[10:12], 0x1101)
	copy(resp[30:60], friendlyName)
	return resp
}
