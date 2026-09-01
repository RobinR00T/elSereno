//go:build offensive

package redlion_test

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"local/elsereno/internal/protocols/redlion/wire"
	"local/elsereno/offensive/confirm"
	rlwrite "local/elsereno/offensive/write/redlion"
)

type fakeDeriver struct{ key []byte }

func (f *fakeDeriver) Derive(_ string, out []byte) error { copy(out, f.key); return nil }

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
	testTarget     = "redlion.test:789"
)

func mintToken(t *testing.T, allowed []rlwrite.AllowedType) string {
	t.Helper()
	mut := rlwrite.SessionMutation(testTarget, allowed)
	tok, err := confirm.ExpectedToken(mut, &fakeDeriver{key: []byte(testDeriverKey)})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func newHandler(t *testing.T, allowed []rlwrite.AllowedType) *rlwrite.WriteGatedHandler {
	t.Helper()
	h := &rlwrite.WriteGatedHandler{
		Target:  testTarget,
		Allowed: allowed,
		Deriver: &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor: &fakeAuditor{},
		SessionConfirm: confirm.Confirm{
			AcceptsWrites: true,
			ConfirmTarget: testTarget,
			ConfirmToken:  mintToken(t, allowed),
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
		fr, err := wire.ReadFrame(conn)
		if len(fr) > 0 {
			r.mu.Lock()
			r.data = append(r.data, fr)
			r.mu.Unlock()
		}
		if err != nil {
			return
		}
	}
}

func (r *frameRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.data)
}

func driveSession(t *testing.T, allowed []rlwrite.AllowedType) (net.Conn, *frameRecorder, <-chan error) {
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
	done := make(chan error, 1)
	go func() { done <- h.Handle(ctx, handlerClientSide, handlerUpstreamSide) }()
	return clientIn, rec, done
}

func cr3(reg uint16, t wire.PacketType, payload ...byte) []byte {
	body := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint16(body[0:2], reg)
	binary.BigEndian.PutUint16(body[2:4], uint16(t))
	copy(body[4:], payload)
	frame := make([]byte, 2+len(body))
	binary.BigEndian.PutUint16(frame[0:2], uint16(len(body)))
	copy(frame[2:], body)
	return frame
}

func waitForOne(t *testing.T, r *frameRecorder) {
	t.Helper()
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if r.count() >= 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("recorder saw 0 frames; wanted >= 1")
}

func expectRefused(t *testing.T, done <-chan error, rec *frameRecorder) {
	t.Helper()
	select {
	case err := <-done:
		if !errors.Is(err, rlwrite.ErrRefused) {
			t.Fatalf("Handle returned %v, want ErrRefused", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Handle did not return after a refused frame")
	}
	if n := rec.count(); n != 0 {
		t.Fatalf("a refused frame leaked %d frame(s) upstream", n)
	}
}

func TestReadTypePasses(t *testing.T) {
	client, rec, _ := driveSession(t, nil)
	if _, err := client.Write(cr3(0x0001, wire.TypeMemRead, 0, 0, 0, 0, 0, 0, 0, 0)); err != nil {
		t.Fatal(err)
	}
	waitForOne(t, rec)
}

func TestAllowedWritePasses(t *testing.T) {
	allow := []rlwrite.AllowedType{{Type: uint16(wire.TypeChunk)}}
	client, rec, _ := driveSession(t, allow)
	if _, err := client.Write(cr3(0x0002, wire.TypeChunk, 1, 2, 3, 4)); err != nil {
		t.Fatal(err)
	}
	waitForOne(t, rec)
}

func TestNonAllowedChunkRefused(t *testing.T) {
	client, rec, done := driveSession(t, nil)
	_, _ = client.Write(cr3(0x0002, wire.TypeChunk, 1, 2, 3, 4))
	expectRefused(t, done, rec)
}

// An unknown/handshake opcode is refused unless allowlisted — the gate
// does not guess that a no-payload opcode is safe.
func TestUnknownTypeRefused(t *testing.T) {
	client, rec, done := driveSession(t, nil)
	_, _ = client.Write(cr3(0x0000, 0x0100)) // handshake, no payload, not allowlisted
	expectRefused(t, done, rec)
}

func TestHandle_RequiresAuthorise(t *testing.T) {
	h := &rlwrite.WriteGatedHandler{Target: testTarget}
	c1, c2 := net.Pipe()
	u1, u2 := net.Pipe()
	t.Cleanup(func() { _ = c1.Close(); _ = c2.Close(); _ = u1.Close(); _ = u2.Close() })
	if err := h.Handle(context.Background(), c2, u1); !errors.Is(err, rlwrite.ErrSessionNotAuthorised) {
		t.Fatalf("Handle without Authorise = %v, want ErrSessionNotAuthorised", err)
	}
}
