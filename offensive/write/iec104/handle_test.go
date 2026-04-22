//go:build offensive

package iec104_test

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"local/elsereno/internal/protocols/iec104/wire"
	"local/elsereno/offensive/confirm"
	iecwrite "local/elsereno/offensive/write/iec104"
)

type fakeDeriver struct{}

func (f *fakeDeriver) Derive(_ string, out []byte) error {
	copy(out, []byte("test-key-32-byte-long--------"))
	return nil
}

type fakeAuditor struct{}

func (f *fakeAuditor) Record(_ context.Context, _ confirm.AuditEvent) error { return nil }

// buildIFrame crafts an I-format APDU with ASDU type = typeID + a
// minimal 6-byte ASDU body (Type+VSQ+COT+CA + IOA stub).
func buildIFrame(typeID uint8) []byte {
	body := []byte{
		typeID,     // ASDU Type
		0x01,       // VSQ = 1 element, no SQ bit
		0x06,       // COT = 6 (activation)
		0x00,       // originator
		0x01, 0x00, // CA = 1
	}
	total := wire.APCILen + len(body)
	out := make([]byte, 0, total)
	out = append(out, wire.Start, uint8(4+len(body))) //nolint:gosec // G115 — test body fixed-size
	out = append(out, 0x00, 0x00, 0x00, 0x00)         // I-format control
	out = append(out, body...)
	return out
}

// buildUFrame returns a U-format STARTDT act.
func buildUFrame() []byte { return wire.BuildSTARTDT() }

func mintToken(t *testing.T, target string, allowed []iecwrite.AllowedASDU) string {
	t.Helper()
	mut := iecwrite.SessionMutation(target, allowed)
	tok, err := confirm.ExpectedToken(mut, &fakeDeriver{})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func driveSession(t *testing.T, allowed []iecwrite.AllowedASDU) net.Conn {
	t.Helper()
	target := "127.0.0.1:2404"
	h := &iecwrite.WriteGatedHandler{
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

func TestUFrameAlwaysPasses(t *testing.T) {
	conn := driveSession(t, nil)
	_ = conn.SetDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := conn.Write(buildUFrame()); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	_, err := conn.Read(buf)
	if err == nil {
		t.Fatal("expected no refusal for U-frame")
	}
}

func TestInterrogationRefusedByDefault(t *testing.T) {
	conn := driveSession(t, nil)
	_ = conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := conn.Write(buildIFrame(iecwrite.TypeIDInterrogation)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("expected refusal, got %v", err)
	}
	if n < wire.APCILen+6 {
		t.Fatalf("refusal too short: %d", n)
	}
	// COT byte is at APCILen + 2; P/N bit should be set + cause 47.
	cot := buf[wire.APCILen+2]
	if cot&0x40 == 0 {
		t.Fatalf("expected P/N bit in COT (got 0x%02x)", cot)
	}
}

func TestInterrogationAllowedWhenInAllowlist(t *testing.T) {
	conn := driveSession(t, []iecwrite.AllowedASDU{{TypeID: iecwrite.TypeIDInterrogation}})
	_ = conn.SetDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := conn.Write(buildIFrame(iecwrite.TypeIDInterrogation)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	_, err := conn.Read(buf)
	if err == nil {
		t.Fatal("expected no refusal for allowed Interrogation")
	}
}

func TestSingleCommandRefusedByDefault(t *testing.T) {
	conn := driveSession(t, nil)
	_ = conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := conn.Write(buildIFrame(iecwrite.TypeIDSingleCommand)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("expected refusal, got %v", err)
	}
	if n < wire.APCILen {
		t.Fatalf("refusal too short")
	}
}

func TestHandle_RequiresAuthorise(t *testing.T) {
	h := &iecwrite.WriteGatedHandler{Target: "x", Deriver: &fakeDeriver{}, Auditor: &fakeAuditor{}}
	cr, _ := io.Pipe()
	rw := struct {
		io.Reader
		io.Writer
	}{cr, io.Discard}
	err := h.Handle(context.Background(), rw, rw)
	if !errors.Is(err, iecwrite.ErrSessionNotAuthorised) {
		t.Fatalf("want ErrSessionNotAuthorised, got %v", err)
	}
}
