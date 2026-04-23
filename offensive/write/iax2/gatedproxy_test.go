//go:build offensive

package iax2_test

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"local/elsereno/internal/protocols/iax2/wire"
	"local/elsereno/offensive/confirm"
	iaxwrite "local/elsereno/offensive/write/iax2"
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

const testDeriverKey = "test-key-32-byte-long--------"

func mintToken(t *testing.T, target string, allowed []iaxwrite.AllowedSubclass) string {
	t.Helper()
	mut := iaxwrite.SessionMutation(target, allowed)
	tok, err := confirm.ExpectedToken(mut, &fakeDeriver{key: []byte(testDeriverKey)})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func newHandler(t *testing.T, target string, allowed []iaxwrite.AllowedSubclass) *iaxwrite.WriteGatedHandler {
	t.Helper()
	h := &iaxwrite.WriteGatedHandler{
		Target:  target,
		Allowed: allowed,
		Deriver: &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor: &fakeAuditor{},
		SessionConfirm: confirm.Confirm{
			AcceptsWrites: true,
			ConfirmTarget: target,
			ConfirmToken:  mintToken(t, target, allowed),
		},
	}
	if err := h.Authorise(context.Background()); err != nil {
		t.Fatal(err)
	}
	return h
}

// datagramRecorder captures every distinct datagram the handler
// writes to upstream or to the client refusal path.
type datagramRecorder struct {
	mu   sync.Mutex
	data [][]byte
}

func (r *datagramRecorder) run(conn net.Conn) {
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			cp := make([]byte, n)
			copy(cp, buf[:n])
			r.mu.Lock()
			r.data = append(r.data, cp)
			r.mu.Unlock()
		}
		if err != nil {
			return
		}
	}
}

func (r *datagramRecorder) snapshot() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([][]byte, len(r.data))
	copy(out, r.data)
	return out
}

// driveSession wires client ↔ handler ↔ upstream via net.Pipe.
// The test holds `clientIn`: writes to it go to the handler;
// reads from it receive refusal frames the handler sends back.
// net.Pipe preserves per-Write boundaries, so each handler read
// is one datagram (matching real UDP semantics).
func driveSession(t *testing.T, allowed []iaxwrite.AllowedSubclass) (net.Conn, *datagramRecorder) {
	t.Helper()
	target := "pbx.test:4569"
	h := newHandler(t, target, allowed)

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

	upstreamRec := &datagramRecorder{}
	go upstreamRec.run(upstreamSide)
	go func() { _ = h.Handle(ctx, handlerClientSide, handlerUpstreamSide) }()

	return clientIn, upstreamRec
}

// buildFullFrame crafts an IAX2 full-frame header with the given
// FrameType + Subclass.
func buildFullFrame(ft wire.FrameType, sub wire.IAXSubclass, srcCall, dstCall uint16, oseqno, iseqno uint8) []byte {
	b := make([]byte, wire.HeaderLen)
	binary.BigEndian.PutUint16(b[0:2], 0x8000|(srcCall&0x7FFF))
	binary.BigEndian.PutUint16(b[2:4], dstCall&0x7FFF)
	binary.BigEndian.PutUint32(b[4:8], 0)
	b[8] = oseqno
	b[9] = iseqno
	b[10] = byte(ft)
	b[11] = byte(sub)
	return b
}

// buildMiniFrame crafts a 4-byte mini-frame (audio). Byte 0's
// high bit is 0 so this parses as ErrMiniFrame.
func buildMiniFrame(callNum uint16, timestamp uint16) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint16(b[0:2], callNum&0x7FFF) // high bit clear
	binary.BigEndian.PutUint16(b[2:4], timestamp)
	return b
}

// waitForFramesOne polls the recorder for at least one datagram.
func waitForFramesOne(t *testing.T, r *datagramRecorder) [][]byte {
	t.Helper()
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		snap := r.snapshot()
		if len(snap) >= 1 {
			return snap
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("recorder saw %d frames; wanted ≥ 1", len(r.snapshot()))
	return nil
}

// ---- AllowlistHash --------------------------------------------

func TestAllowlistHash_OrderInsensitive(t *testing.T) {
	a := []iaxwrite.AllowedSubclass{
		{Subclass: wire.IAXNew},
		{Subclass: wire.IAXRegreq},
	}
	b := []iaxwrite.AllowedSubclass{
		{Subclass: wire.IAXRegreq},
		{Subclass: wire.IAXNew},
	}
	if iaxwrite.AllowlistHash("t", a) != iaxwrite.AllowlistHash("t", b) {
		t.Fatal("hash depends on input order")
	}
}

func TestAllowlistHash_DifferentTarget(t *testing.T) {
	a := []iaxwrite.AllowedSubclass{{Subclass: wire.IAXNew}}
	if iaxwrite.AllowlistHash("host-a:4569", a) == iaxwrite.AllowlistHash("host-b:4569", a) {
		t.Fatal("hash should vary with target")
	}
}

// ---- Authorise ------------------------------------------------

func TestAuthorise_HappyPath(t *testing.T) {
	target := "pbx.test:4569"
	allowed := []iaxwrite.AllowedSubclass{{Subclass: wire.IAXNew}}
	h := newHandler(t, target, allowed)
	if err := h.Authorise(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestAuthorise_DeniedBadToken(t *testing.T) {
	target := "pbx.test:4569"
	h := &iaxwrite.WriteGatedHandler{
		Target:  target,
		Deriver: &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor: &fakeAuditor{},
		SessionConfirm: confirm.Confirm{
			AcceptsWrites: true,
			ConfirmTarget: target,
			ConfirmToken:  "wrong",
		},
	}
	if err := h.Authorise(context.Background()); err == nil {
		t.Fatal("expected bad-token error")
	}
}

func TestHandle_UnauthorisedErrors(t *testing.T) {
	h := &iaxwrite.WriteGatedHandler{
		Target:  "pbx.test:4569",
		Deriver: &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor: &fakeAuditor{},
	}
	err := h.Handle(context.Background(), &ioPair{}, &ioPair{})
	if err == nil {
		t.Fatal("expected ErrSessionNotAuthorised")
	}
}

type ioPair struct{}

func (*ioPair) Read(_ []byte) (int, error)  { return 0, io.EOF }
func (*ioPair) Write(b []byte) (int, error) { return len(b), nil }

// ---- Routing: always-safe frames ------------------------------

func TestMiniFrameAlwaysPasses(t *testing.T) {
	client, upstream := driveSession(t, nil)
	mini := buildMiniFrame(0x1234, 12345)
	_, _ = client.Write(mini)
	frames := waitForFramesOne(t, upstream)
	if len(frames[0]) != 4 {
		t.Fatalf("expected 4-byte mini-frame forwarded; got %d bytes", len(frames[0]))
	}
}

func TestHANGUPAlwaysPasses(t *testing.T) {
	client, upstream := driveSession(t, nil)
	hangup := buildFullFrame(wire.FrameTypeIAX, wire.IAXHangup, 0x1000, 0x2000, 1, 1)
	_, _ = client.Write(hangup)
	frames := waitForFramesOne(t, upstream)
	if len(frames[0]) != wire.HeaderLen {
		t.Fatalf("HANGUP should be a 12-byte frame; got %d", len(frames[0]))
	}
}

func TestACKAlwaysPasses(t *testing.T) {
	client, upstream := driveSession(t, nil)
	ack := buildFullFrame(wire.FrameTypeIAX, wire.IAXAck, 0x1000, 0x2000, 2, 1)
	_, _ = client.Write(ack)
	frames := waitForFramesOne(t, upstream)
	if len(frames[0]) != wire.HeaderLen {
		t.Fatalf("ACK should be a 12-byte frame; got %d", len(frames[0]))
	}
}

func TestVoiceFrameAlwaysPasses(t *testing.T) {
	// FrameType Voice (0x02) is never gated — media always flows.
	client, upstream := driveSession(t, nil)
	voice := buildFullFrame(wire.FrameTypeVoice, 0, 0x1000, 0x2000, 5, 5)
	_, _ = client.Write(voice)
	frames := waitForFramesOne(t, upstream)
	if len(frames[0]) != wire.HeaderLen {
		t.Fatalf("Voice frame should be forwarded; got %d bytes", len(frames[0]))
	}
}

// ---- Routing: gated subclasses --------------------------------

func TestNEWAllowedWithExplicitAllowlist(t *testing.T) {
	client, upstream := driveSession(t, []iaxwrite.AllowedSubclass{{Subclass: wire.IAXNew}})
	newFrame := buildFullFrame(wire.FrameTypeIAX, wire.IAXNew, 0x0ABC, 0, 0, 0)
	_, _ = client.Write(newFrame)
	frames := waitForFramesOne(t, upstream)
	if frames[0][11] != byte(wire.IAXNew) {
		t.Fatalf("expected IAXNew byte 0x%02x, got 0x%02x", wire.IAXNew, frames[0][11])
	}
}

func TestNEWBlockedReturnsHANGUP(t *testing.T) {
	client, upstream := driveSession(t, nil) // empty allowlist
	srcCall := uint16(0x0ABC)
	newFrame := buildFullFrame(wire.FrameTypeIAX, wire.IAXNew, srcCall, 0, 0, 0)
	_, _ = client.Write(newFrame)

	// Client should receive a HANGUP back.
	_ = client.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 12)
	n, err := io.ReadFull(client, buf)
	if err != nil {
		t.Fatalf("read HANGUP back: %v (got %d bytes)", err, n)
	}
	if buf[11] != byte(wire.IAXHangup) {
		t.Fatalf("refusal should be HANGUP (0x%02x); got 0x%02x", wire.IAXHangup, buf[11])
	}
	// DstCallNum in the reply should equal the client's
	// SrcCallNum — so the client routes the HANGUP to its
	// pending call.
	dst := binary.BigEndian.Uint16(buf[2:4]) & 0x7FFF
	if dst != srcCall {
		t.Fatalf("HANGUP Dst = 0x%04x, want client's Src 0x%04x", dst, srcCall)
	}
	// Upstream should have seen NOTHING.
	time.Sleep(50 * time.Millisecond)
	if got := upstream.snapshot(); len(got) != 0 {
		t.Fatalf("upstream saw %d datagrams for a blocked NEW", len(got))
	}
}

func TestREGREQBlockedReturnsHANGUP(t *testing.T) {
	client, upstream := driveSession(t, []iaxwrite.AllowedSubclass{{Subclass: wire.IAXNew}}) // NEW allowed, REGREQ not
	regreq := buildFullFrame(wire.FrameTypeIAX, wire.IAXRegreq, 0x0DEF, 0, 0, 0)
	_, _ = client.Write(regreq)
	_ = client.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 12)
	n, err := io.ReadFull(client, buf)
	if err != nil {
		t.Fatalf("read HANGUP back: %v (%d bytes)", err, n)
	}
	if buf[11] != byte(wire.IAXHangup) {
		t.Fatalf("REGREQ refusal expected HANGUP; got 0x%02x", buf[11])
	}
	time.Sleep(50 * time.Millisecond)
	if got := upstream.snapshot(); len(got) != 0 {
		t.Fatalf("upstream saw REGREQ it shouldn't have")
	}
}

func TestREGREQAllowedWithExplicitAllowlist(t *testing.T) {
	client, upstream := driveSession(t, []iaxwrite.AllowedSubclass{{Subclass: wire.IAXRegreq}})
	regreq := buildFullFrame(wire.FrameTypeIAX, wire.IAXRegreq, 0x0DEF, 0, 0, 0)
	_, _ = client.Write(regreq)
	frames := waitForFramesOne(t, upstream)
	if frames[0][11] != byte(wire.IAXRegreq) {
		t.Fatalf("upstream saw subclass 0x%02x; want REGREQ 0x%02x", frames[0][11], wire.IAXRegreq)
	}
}

// ---- Mixed stream ---------------------------------------------

func TestMixedStream_MiniThenBlockedNEW(t *testing.T) {
	client, upstream := driveSession(t, nil)
	mini := buildMiniFrame(0x1000, 999)
	_, _ = client.Write(mini)
	// Give the handler a tick to forward the mini.
	time.Sleep(20 * time.Millisecond)
	// Then send a NEW that should be blocked.
	newF := buildFullFrame(wire.FrameTypeIAX, wire.IAXNew, 0x1111, 0, 0, 0)
	_, _ = client.Write(newF)

	// Upstream should see only the mini-frame.
	frames := waitForFramesOne(t, upstream)
	if len(frames[0]) != 4 {
		t.Fatalf("first upstream frame should be 4-byte mini; got %d", len(frames[0]))
	}
	// Client should see a HANGUP.
	_ = client.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 12)
	_, err := io.ReadFull(client, buf)
	if err != nil {
		t.Fatalf("read HANGUP: %v", err)
	}
	if buf[11] != byte(wire.IAXHangup) {
		t.Fatalf("HANGUP expected; got 0x%02x", buf[11])
	}
}
