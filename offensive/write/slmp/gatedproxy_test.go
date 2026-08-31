//go:build offensive

package slmp_test

import (
	"context"
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"

	"local/elsereno/internal/protocols/slmp/wire"
	"local/elsereno/offensive/confirm"
	slmpwrite "local/elsereno/offensive/write/slmp"
)

// ---- fakes ----------------------------------------------------

type fakeDeriver struct{ key []byte }

func (f *fakeDeriver) Derive(_ string, out []byte) error {
	copy(out, f.key)
	return nil
}

type fakeAuditor struct {
	mu     sync.Mutex
	events []confirm.AuditEvent
}

func (f *fakeAuditor) Record(_ context.Context, ev confirm.AuditEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, ev)
	return nil
}

const (
	testDeriverKey = "test-key-32-byte-long--------"
	testTarget     = "slmp.test:5007"
)

func mintToken(t *testing.T, target string, allowed []slmpwrite.AllowedCommand) string {
	t.Helper()
	mut := slmpwrite.SessionMutation(target, allowed)
	tok, err := confirm.ExpectedToken(mut, &fakeDeriver{key: []byte(testDeriverKey)})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func newHandler(t *testing.T, allowed []slmpwrite.AllowedCommand) *slmpwrite.WriteGatedHandler {
	t.Helper()
	h := &slmpwrite.WriteGatedHandler{
		Target:  testTarget,
		Allowed: allowed,
		Deriver: &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor: &fakeAuditor{},
		SessionConfirm: confirm.Confirm{
			AcceptsWrites: true,
			ConfirmTarget: testTarget,
			ConfirmToken:  mintToken(t, testTarget, allowed),
		},
	}
	if err := h.Authorise(context.Background()); err != nil {
		t.Fatal(err)
	}
	return h
}

type frameRecorder struct {
	mu   sync.Mutex
	data [][]byte
}

func (r *frameRecorder) run(conn net.Conn) {
	for {
		frame, err := wire.ReadFrame(conn)
		if len(frame) > 0 {
			r.mu.Lock()
			r.data = append(r.data, frame)
			r.mu.Unlock()
		}
		if err != nil {
			return
		}
	}
}

func (r *frameRecorder) snapshot() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([][]byte, len(r.data))
	copy(out, r.data)
	return out
}

func driveSession(t *testing.T, allowed []slmpwrite.AllowedCommand) (net.Conn, *frameRecorder) {
	t.Helper()
	h := newHandler(t, allowed)
	clientIn, handlerClientSide := net.Pipe()
	handlerUpstreamSide, upstreamSide := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = clientIn.Close()
		_ = handlerClientSide.Close()
		_ = handlerUpstreamSide.Close()
		_ = upstreamSide.Close()
	})
	rec := &frameRecorder{}
	go rec.run(upstreamSide)
	go func() { _ = h.Handle(ctx, handlerClientSide, handlerUpstreamSide) }()
	return clientIn, rec
}

// buildSLMP crafts a 3E-binary request carrying the given command
// (subcommand 0) plus optional payload.
func buildSLMP(command uint16, payload ...byte) []byte {
	dataLen := 2 + 2 + 2 + len(payload) // monitoring + command + subcommand + payload
	frame := make([]byte, 9+dataLen)
	binary.LittleEndian.PutUint16(frame[0:2], wire.SubheaderRequestLE)
	frame[3] = 0xFF
	binary.LittleEndian.PutUint16(frame[4:6], 0x03FF)
	binary.LittleEndian.PutUint16(frame[7:9], uint16(dataLen))
	binary.LittleEndian.PutUint16(frame[11:13], command)
	copy(frame[15:], payload)
	return frame
}

const shortPause = 100 * time.Millisecond

func readOne(t *testing.T, c net.Conn) []byte {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	frame, err := wire.ReadFrame(c)
	if err != nil {
		t.Fatalf("expected a refusal frame from the client side: %v", err)
	}
	return frame
}

func waitForOneFrame(t *testing.T, r *frameRecorder) [][]byte {
	t.Helper()
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if snap := r.snapshot(); len(snap) >= 1 {
			return snap
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("recorder saw 0 frames; wanted >= 1")
	return nil
}

// ---- tests ----------------------------------------------------

func TestAllowlistHash_OrderInsensitive(t *testing.T) {
	a := []slmpwrite.AllowedCommand{{Command: 0x1401}, {Command: 0x1002}}
	b := []slmpwrite.AllowedCommand{{Command: 0x1002}, {Command: 0x1401}}
	if slmpwrite.AllowlistHash(testTarget, a) != slmpwrite.AllowlistHash(testTarget, b) {
		t.Fatal("AllowlistHash is order-sensitive")
	}
	if slmpwrite.AllowlistHash(testTarget, a) == slmpwrite.AllowlistHash("other:5007", a) {
		t.Fatal("AllowlistHash ignores the target")
	}
}

func TestAuthorise_DeniedBadToken(t *testing.T) {
	h := &slmpwrite.WriteGatedHandler{
		Target:  testTarget,
		Deriver: &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor: &fakeAuditor{},
		SessionConfirm: confirm.Confirm{
			AcceptsWrites: true,
			ConfirmTarget: testTarget,
			ConfirmToken:  "not-the-expected-token",
		},
	}
	if err := h.Authorise(context.Background()); err == nil {
		t.Fatal("Authorise accepted a bad token")
	}
}

func TestReadPassesUpstream(t *testing.T) {
	client, rec := driveSession(t, nil)
	req := buildSLMP(uint16(wire.CmdDeviceReadBatch), 0x00, 0x00) // Device Read
	if _, err := client.Write(req); err != nil {
		t.Fatal(err)
	}
	got := waitForOneFrame(t, rec)
	if len(got[0]) != len(req) {
		t.Fatalf("forwarded %d bytes, want %d", len(got[0]), len(req))
	}
}

func TestAllowedWritePassesUpstream(t *testing.T) {
	allow := []slmpwrite.AllowedCommand{{Command: uint16(wire.CmdDeviceWriteBatch)}}
	client, rec := driveSession(t, allow)
	req := buildSLMP(uint16(wire.CmdDeviceWriteBatch), 0xA8, 0x00, 0x00, 0x00, 0x90, 0x01, 0x00, 0x34, 0x12)
	if _, err := client.Write(req); err != nil {
		t.Fatal(err)
	}
	got := waitForOneFrame(t, rec)
	if cmd, _ := wire.ExtractCommand(got[0]); cmd != wire.CmdDeviceWriteBatch {
		t.Fatalf("forwarded command = 0x%04x, want Device Write Batch", uint16(cmd))
	}
}

func TestNonAllowedWriteRefused(t *testing.T) {
	client, rec := driveSession(t, nil) // empty allowlist
	req := buildSLMP(uint16(wire.CmdDeviceWriteBatch), 0xA8, 0x00, 0x00, 0x00, 0x90, 0x01, 0x00, 0xFF, 0xFF)
	if _, err := client.Write(req); err != nil {
		t.Fatal(err)
	}
	ref := readOne(t, client)
	if binary.LittleEndian.Uint16(ref[0:2]) != wire.SubheaderResponseLE {
		t.Errorf("refusal is not an SLMP response frame")
	}
	if ec := binary.LittleEndian.Uint16(ref[9:11]); ec != wire.EndCodeRefused {
		t.Errorf("refusal end code = 0x%04x, want 0x%04x", ec, wire.EndCodeRefused)
	}
	time.Sleep(shortPause)
	if snap := rec.snapshot(); len(snap) != 0 {
		t.Fatalf("a refused write leaked %d frame(s) upstream", len(snap))
	}
}

func TestUnknownCommandRefused(t *testing.T) {
	client, rec := driveSession(t, []slmpwrite.AllowedCommand{{Command: uint16(wire.CmdDeviceWriteBatch)}})
	req := buildSLMP(0x9999) // not in any table
	if _, err := client.Write(req); err != nil {
		t.Fatal(err)
	}
	ref := readOne(t, client)
	if binary.LittleEndian.Uint16(ref[9:11]) != wire.EndCodeRefused {
		t.Errorf("unknown-command refusal end code wrong")
	}
	time.Sleep(shortPause)
	if snap := rec.snapshot(); len(snap) != 0 {
		t.Fatalf("an unknown command leaked %d frame(s) upstream", len(snap))
	}
}

func TestHandle_RequiresAuthorise(t *testing.T) {
	h := &slmpwrite.WriteGatedHandler{Target: testTarget}
	c1, c2 := net.Pipe()
	u1, u2 := net.Pipe()
	t.Cleanup(func() { _ = c1.Close(); _ = c2.Close(); _ = u1.Close(); _ = u2.Close() })
	if err := h.Handle(context.Background(), c2, u1); err != slmpwrite.ErrSessionNotAuthorised {
		t.Fatalf("Handle without Authorise returned %v, want ErrSessionNotAuthorised", err)
	}
}
