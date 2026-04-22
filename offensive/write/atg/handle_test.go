//go:build offensive

package atg_test

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"local/elsereno/offensive/confirm"
	atgwrite "local/elsereno/offensive/write/atg"
)

type fakeDeriver struct{}

func (f *fakeDeriver) Derive(_ string, out []byte) error {
	copy(out, []byte("test-key-32-byte-long--------"))
	return nil
}

type fakeAuditor struct{}

func (f *fakeAuditor) Record(_ context.Context, _ confirm.AuditEvent) error { return nil }

func mintToken(t *testing.T, target string, allowed []atgwrite.AllowedCommand) string {
	t.Helper()
	mut := atgwrite.SessionMutation(target, allowed)
	tok, err := confirm.ExpectedToken(mut, &fakeDeriver{})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func driveSession(t *testing.T, allowed []atgwrite.AllowedCommand) net.Conn {
	t.Helper()
	target := "127.0.0.1:10001"
	h := &atgwrite.WriteGatedHandler{
		Target:  target,
		Allowed: allowed,
		Deriver: &fakeDeriver{},
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
	clientPipe, handlerClientSide := net.Pipe()
	upstreamReader, upstreamWriter := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = clientPipe.Close()
		_ = handlerClientSide.Close()
		_ = upstreamReader.Close()
		_ = upstreamWriter.Close()
	})
	go func() { _, _ = io.Copy(io.Discard, upstreamReader) }()
	go func() {
		_ = h.Handle(ctx, handlerClientSide, upstreamWriter)
	}()
	return clientPipe
}

func TestInfoCommandPasses(t *testing.T) {
	conn := driveSession(t, nil)
	_ = conn.SetDeadline(time.Now().Add(300 * time.Millisecond))
	cmd := []byte{atgwrite.SOH, 'I', '2', '0', '1', '0', '0', atgwrite.CR}
	if _, err := conn.Write(cmd); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	_, err := conn.Read(buf)
	if err == nil {
		t.Fatal("expected no refusal for I command")
	}
}

func TestVolumeCommandRefusedByDefault(t *testing.T) {
	conn := driveSession(t, nil)
	_ = conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
	cmd := []byte{atgwrite.SOH, 'V', '2', '0', '1', '0', '0', atgwrite.CR}
	if _, err := conn.Write(cmd); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("expected refusal, got %v", err)
	}
	if n < 10 {
		t.Fatalf("refusal too short: %d", n)
	}
	if buf[0] != atgwrite.SOH {
		t.Fatalf("refusal must start with SOH, got 0x%02x", buf[0])
	}
	// Expect "9999" error header at offset 1..4.
	if string(buf[1:5]) != "9999" {
		t.Fatalf("expected 9999 header, got %q", string(buf[1:5]))
	}
}

func TestVolumeAllowedWhenInAllowlist(t *testing.T) {
	conn := driveSession(t, []atgwrite.AllowedCommand{{Prefix: 'V'}})
	_ = conn.SetDeadline(time.Now().Add(300 * time.Millisecond))
	cmd := []byte{atgwrite.SOH, 'V', '2', '0', '1', '0', '0', atgwrite.CR}
	if _, err := conn.Write(cmd); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	_, err := conn.Read(buf)
	if err == nil {
		t.Fatal("expected no refusal for allowed V command")
	}
}

func TestSetCommandRefused(t *testing.T) {
	conn := driveSession(t, nil)
	_ = conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
	cmd := []byte{atgwrite.SOH, 'S', '1', '0', '1', '0', '0', atgwrite.CR}
	if _, err := conn.Write(cmd); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("expected refusal, got %v", err)
	}
	if n < 10 {
		t.Fatalf("refusal too short")
	}
}

func TestHandle_RequiresAuthorise(t *testing.T) {
	h := &atgwrite.WriteGatedHandler{Target: "x", Deriver: &fakeDeriver{}, Auditor: &fakeAuditor{}}
	cr, _ := io.Pipe()
	rw := struct {
		io.Reader
		io.Writer
	}{cr, io.Discard}
	err := h.Handle(context.Background(), rw, rw)
	if !errors.Is(err, atgwrite.ErrSessionNotAuthorised) {
		t.Fatalf("want ErrSessionNotAuthorised, got %v", err)
	}
}
