//go:build offensive

package codesys_test

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"local/elsereno/internal/protocols/codesys/wire"
	"local/elsereno/offensive/confirm"
	cswrite "local/elsereno/offensive/write/codesys"
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
	testTarget     = "codesys.test:11740"
)

func mintToken(t *testing.T, allowed []cswrite.AllowedCommand) string {
	t.Helper()
	mut := cswrite.SessionMutation(testTarget, allowed)
	tok, err := confirm.ExpectedToken(mut, &fakeDeriver{key: []byte(testDeriverKey)})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func newHandler(t *testing.T, allowed []cswrite.AllowedCommand) *cswrite.WriteGatedHandler {
	t.Helper()
	h := &cswrite.WriteGatedHandler{
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

// byteRecorder accumulates everything forwarded upstream.
type byteRecorder struct {
	mu   sync.Mutex
	data []byte
}

func (r *byteRecorder) run(conn net.Conn) {
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			r.mu.Lock()
			r.data = append(r.data, buf[:n]...)
			r.mu.Unlock()
		}
		if err != nil {
			return
		}
	}
}

func (r *byteRecorder) len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.data)
}

func driveSession(t *testing.T, allowed []cswrite.AllowedCommand) (net.Conn, *byteRecorder, <-chan error) {
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
	rec := &byteRecorder{}
	go rec.run(upstreamSide)
	done := make(chan error, 1)
	go func() { done <- h.Handle(ctx, handlerClientSide, handlerUpstreamSide) }()
	return clientIn, rec, done
}

var magicA = [2]byte{0x55, 0xcd}

// l7 builds a minimal L7 service header framed by an L2/L3-ish prefix
// so the stream resembles real traffic (the gate ignores the prefix
// and locates L7 by magic).
func l7(service, cmd byte, payload ...byte) []byte {
	prefix := []byte{0x00, 0x01, 0x17, 0xe8, 0x40, 0x00, 0x00, 0x00} // L2 magic + junk
	hdr := []byte{magicA[0], magicA[1], 0x00, 0x00, service, 0x00, cmd, 0x00}
	out := append(prefix, hdr...)
	return append(out, payload...)
}

func waitForBytes(t *testing.T, r *byteRecorder, min int) {
	t.Helper()
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if r.len() >= min {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("recorder saw %d bytes; wanted >= %d", r.len(), min)
}

func expectRefused(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if !errors.Is(err, cswrite.ErrRefused) {
			t.Fatalf("Handle returned %v, want ErrRefused", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Handle did not return after a refused stream")
	}
}

func TestReadCommandPasses(t *testing.T) {
	client, rec, _ := driveSession(t, nil)
	frame := l7(wire.SvcCmpApp, 0x14) // ReadStatus
	if _, err := client.Write(frame); err != nil {
		t.Fatal(err)
	}
	waitForBytes(t, rec, len(frame))
}

func TestAllowedWritePasses(t *testing.T) {
	allow := []cswrite.AllowedCommand{{Service: wire.SvcCmpApp, Cmd: 0x10}} // Start
	client, rec, _ := driveSession(t, allow)
	frame := l7(wire.SvcCmpApp, 0x10)
	if _, err := client.Write(frame); err != nil {
		t.Fatal(err)
	}
	waitForBytes(t, rec, len(frame))
}

func TestNonAllowedWriteRefused(t *testing.T) {
	client, rec, done := driveSession(t, nil)
	// Download (0x05) is not allowlisted.
	if _, err := client.Write(l7(wire.SvcCmpApp, 0x05, 1, 2, 3)); err != nil {
		// Write may error once forward drops the pipe; the refusal is
		// asserted via done below.
		_ = err
	}
	expectRefused(t, done)
	if n := rec.len(); n != 0 {
		t.Fatalf("a refused write leaked %d bytes upstream", n)
	}
}

func TestUnknownCommandRefused(t *testing.T) {
	client, _, done := driveSession(t, nil)
	// service 0x03 (CmpMonitor) is not in either category table.
	_, _ = client.Write(l7(0x03, 0x01))
	expectRefused(t, done)
}

// A decoy read prepended to a real (non-allowlisted) write must still
// refuse: the write header is located regardless of the decoy.
func TestDecoyReadDoesNotHideWrite(t *testing.T) {
	client, rec, done := driveSession(t, nil)
	decoy := l7(wire.SvcCmpApp, 0x14) // ReadStatus
	// Second L7 header (Stop, a write) inside the same stream.
	stop := []byte{magicA[0], magicA[1], 0, 0, wire.SvcCmpApp, 0, 0x11, 0}
	_, _ = client.Write(append(decoy, stop...))
	expectRefused(t, done)
	if rec.len() != 0 {
		t.Fatalf("decoy leaked %d bytes upstream before refusal", rec.len())
	}
}

func TestHandle_RequiresAuthorise(t *testing.T) {
	h := &cswrite.WriteGatedHandler{Target: testTarget}
	c1, c2 := net.Pipe()
	u1, u2 := net.Pipe()
	t.Cleanup(func() { _ = c1.Close(); _ = c2.Close(); _ = u1.Close(); _ = u2.Close() })
	if err := h.Handle(context.Background(), c2, u1); !errors.Is(err, cswrite.ErrSessionNotAuthorised) {
		t.Fatalf("Handle without Authorise = %v, want ErrSessionNotAuthorised", err)
	}
}
