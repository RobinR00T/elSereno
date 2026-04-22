//go:build offensive

package hartip_test

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"local/elsereno/internal/protocols/hartip/wire"
	"local/elsereno/offensive/confirm"
	hartwrite "local/elsereno/offensive/write/hartip"
)

type fakeDeriver struct{}

func (f *fakeDeriver) Derive(_ string, out []byte) error {
	copy(out, []byte("test-key-32-byte-long--------"))
	return nil
}

type fakeAuditor struct{}

func (f *fakeAuditor) Record(_ context.Context, _ confirm.AuditEvent) error { return nil }

// buildTokenPass crafts a HART-IP TokenPassPDU request with the
// given HART command in a long-frame PDU.
func buildTokenPass(cmd uint8) []byte {
	// HART long-frame body: delim 0x82 + 5 bytes address + cmd + bc=0.
	hart := []byte{0x82, 0x00, 0x00, 0x00, 0x00, 0x00, cmd, 0x00}
	total := wire.HeaderLen + len(hart)
	out := make([]byte, total)
	out[0] = wire.Version
	out[1] = wire.MsgRequest
	out[2] = wire.IDTokenPassPDU
	out[3] = 0x00
	binary.BigEndian.PutUint16(out[4:6], 1)
	binary.BigEndian.PutUint16(out[6:8], uint16(total)) //nolint:gosec // G115 — test body fixed-size
	copy(out[wire.HeaderLen:], hart)
	return out
}

// buildSessionInit crafts a SessionInitiate request.
func buildSessionInit() []byte { return wire.BuildSessionInitiate(1) }

func mintToken(t *testing.T, target string, allowed []hartwrite.AllowedCommand) string {
	t.Helper()
	mut := hartwrite.SessionMutation(target, allowed)
	tok, err := confirm.ExpectedToken(mut, &fakeDeriver{})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func driveSession(t *testing.T, allowed []hartwrite.AllowedCommand) net.Conn {
	t.Helper()
	target := "127.0.0.1:5094"
	h := &hartwrite.WriteGatedHandler{
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

func TestSessionInitPasses(t *testing.T) {
	conn := driveSession(t, nil)
	_ = conn.SetDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := conn.Write(buildSessionInit()); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	_, err := conn.Read(buf)
	if err == nil {
		t.Fatal("expected no refusal for SessionInitiate")
	}
}

func TestReadCommandAlwaysPasses(t *testing.T) {
	conn := driveSession(t, nil)
	_ = conn.SetDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := conn.Write(buildTokenPass(hartwrite.HARTCmdReadPrimaryVariable)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	_, err := conn.Read(buf)
	if err == nil {
		t.Fatal("expected no refusal for Cmd 1 (read)")
	}
}

func TestWriteCommandRefusedByDefault(t *testing.T) {
	conn := driveSession(t, nil)
	_ = conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := conn.Write(buildTokenPass(hartwrite.HARTCmdDeviceReset)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("expected refusal, got %v", err)
	}
	if n < wire.HeaderLen+4 {
		t.Fatalf("refusal too short: %d", n)
	}
	// Response code 1 = command-not-implemented (0x40) at HART body
	// offset 8 (long frame — our request uses 0x82).
	hartBody := buf[wire.HeaderLen:n]
	var rc1 uint8
	if hartBody[0]&0x80 != 0 && len(hartBody) >= 9 {
		rc1 = hartBody[8]
	} else {
		rc1 = hartBody[4]
	}
	if rc1&0x40 == 0 {
		t.Fatalf("expected response-code command-not-implemented, got 0x%02x", rc1)
	}
}

func TestWriteCommandAllowed(t *testing.T) {
	conn := driveSession(t, []hartwrite.AllowedCommand{{HARTCmd: hartwrite.HARTCmdDeviceReset}})
	_ = conn.SetDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := conn.Write(buildTokenPass(hartwrite.HARTCmdDeviceReset)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	_, err := conn.Read(buf)
	if err == nil {
		t.Fatal("expected no refusal for allowed command")
	}
}

func TestHandle_RequiresAuthorise(t *testing.T) {
	h := &hartwrite.WriteGatedHandler{Target: "x", Deriver: &fakeDeriver{}, Auditor: &fakeAuditor{}}
	cr, _ := io.Pipe()
	rw := struct {
		io.Reader
		io.Writer
	}{cr, io.Discard}
	err := h.Handle(context.Background(), rw, rw)
	if !errors.Is(err, hartwrite.ErrSessionNotAuthorised) {
		t.Fatalf("want ErrSessionNotAuthorised, got %v", err)
	}
}
