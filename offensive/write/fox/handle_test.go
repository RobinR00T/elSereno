//go:build offensive

package fox_test

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"local/elsereno/offensive/confirm"
	foxwrite "local/elsereno/offensive/write/fox"
)

type fakeDeriver struct{}

func (f *fakeDeriver) Derive(_ string, out []byte) error {
	copy(out, []byte("test-key-32-byte-long--------"))
	return nil
}

type fakeAuditor struct{}

func (f *fakeAuditor) Record(_ context.Context, _ confirm.AuditEvent) error { return nil }

func mintToken(t *testing.T, target string, allowed []foxwrite.AllowedCommand) string {
	t.Helper()
	mut := foxwrite.SessionMutation(target, allowed)
	tok, err := confirm.ExpectedToken(mut, &fakeDeriver{})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func driveSession(t *testing.T, allowed []foxwrite.AllowedCommand) net.Conn {
	t.Helper()
	target := "127.0.0.1:1911"
	h := &foxwrite.WriteGatedHandler{
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

func TestHelloPassesThrough(t *testing.T) {
	conn := driveSession(t, nil)
	_ = conn.SetDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := conn.Write([]byte("fox hello\n")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	_, err := conn.Read(buf)
	if err == nil {
		t.Fatal("expected no refusal for fox hello")
	}
}

func TestPropertySetRefusedByDefault(t *testing.T) {
	conn := driveSession(t, nil)
	_ = conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := conn.Write([]byte("fox property set {slot:/Drivers:foo} 42\n")); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	reply, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("expected refusal line, got %v", err)
	}
	if reply != "fox a 0 -1 fox denied\n" {
		t.Fatalf("refusal = %q, want %q", reply, "fox a 0 -1 fox denied\n")
	}
}

func TestPropertySetAllowed(t *testing.T) {
	conn := driveSession(t, []foxwrite.AllowedCommand{{Verb: "property"}})
	_ = conn.SetDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := conn.Write([]byte("fox property set {slot:/Drivers:foo} 42\n")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	_, err := conn.Read(buf)
	if err == nil {
		t.Fatal("expected no refusal for allowed property verb")
	}
}

func TestSessionBeginRefused(t *testing.T) {
	conn := driveSession(t, nil)
	_ = conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := conn.Write([]byte("fox session begin\n")); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	reply, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if reply != "fox a 0 -1 fox denied\n" {
		t.Fatalf("refusal = %q", reply)
	}
}

func TestListCommandAlwaysPasses(t *testing.T) {
	conn := driveSession(t, nil)
	_ = conn.SetDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := conn.Write([]byte("fox list /\n")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	_, err := conn.Read(buf)
	if err == nil {
		t.Fatal("expected no refusal for fox list")
	}
}

func TestHandle_RequiresAuthorise(t *testing.T) {
	h := &foxwrite.WriteGatedHandler{Target: "x", Deriver: &fakeDeriver{}, Auditor: &fakeAuditor{}}
	cr, _ := io.Pipe()
	rw := struct {
		io.Reader
		io.Writer
	}{cr, io.Discard}
	err := h.Handle(context.Background(), rw, rw)
	if !errors.Is(err, foxwrite.ErrSessionNotAuthorised) {
		t.Fatalf("want ErrSessionNotAuthorised, got %v", err)
	}
}
