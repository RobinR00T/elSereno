//go:build offensive

package dnp3_test

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"local/elsereno/internal/protocols/dnp3/wire"
	"local/elsereno/offensive/confirm"
	dnpwrite "local/elsereno/offensive/write/dnp3"
)

type fakeDeriver struct{ key []byte }

func (f *fakeDeriver) Derive(_ string, out []byte) error { copy(out, f.key); return nil }

type fakeAuditor struct{ events []confirm.AuditEvent }

func (f *fakeAuditor) Record(_ context.Context, ev confirm.AuditEvent) error {
	f.events = append(f.events, ev)
	return nil
}

// buildUserDataFrame crafts a DNP3 link-layer user-data frame
// with the given app-layer FC. Link control = 0xC4 (DIR=1,PRM=1,
// unconfirmed user data = FC 4).
func buildUserDataFrame(appFC uint8) []byte {
	userData := []byte{
		0xC0,  // transport header
		0xC0,  // AC
		appFC, // FC
		0x00,  // placeholder object
	}
	frame := make([]byte, wire.HeaderLen+len(userData))
	frame[0] = wire.StartBytes[0]
	frame[1] = wire.StartBytes[1]
	frame[2] = uint8(5 + len(userData)) // #nosec G115 -- test body fixed-size
	frame[3] = 0xC4
	binary.LittleEndian.PutUint16(frame[4:6], 0x0001)
	binary.LittleEndian.PutUint16(frame[6:8], 0x0002)
	copy(frame[wire.HeaderLen:], userData)
	return frame
}

func mintToken(t *testing.T, target string, allowed []dnpwrite.AllowedControl) string {
	t.Helper()
	mut := dnpwrite.SessionMutation(target, allowed)
	tok, err := confirm.ExpectedToken(mut, &fakeDeriver{key: []byte("test-key-32-byte-long--------")})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func driveSession(t *testing.T, allowedApp []dnpwrite.AllowedAppFunction) net.Conn {
	t.Helper()
	target := "127.0.0.1:20000"
	// The link-layer allowlist stays nil across the test matrix
	// — the gate's default policy accepts Confirmed + Unconfirmed
	// User Data, and the app-layer allowlist is what every test
	// needs to vary.
	var allowedLink []dnpwrite.AllowedControl
	h := &dnpwrite.WriteGatedHandler{
		Target:       target,
		Allowed:      allowedLink,
		AllowedAppFC: allowedApp,
		Deriver:      &fakeDeriver{key: []byte("test-key-32-byte-long--------")},
		Auditor:      &fakeAuditor{},
		SessionConfirm: confirm.Confirm{
			AcceptsWrites: true,
			ConfirmTarget: target,
			ConfirmToken:  mintToken(t, target, allowedLink),
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

func TestReadAlwaysPasses(t *testing.T) {
	conn := driveSession(t, nil) // empty allowlists
	msg := buildUserDataFrame(dnpwrite.AppFCRead)
	_ = conn.SetDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	_, err := conn.Read(buf)
	if err == nil {
		t.Fatal("expected no refusal on Read")
	}
}

func TestWriteWithoutAllowRefused(t *testing.T) {
	conn := driveSession(t, nil) // Write not in allowlist
	msg := buildUserDataFrame(dnpwrite.AppFCWrite)
	_ = conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("expected refusal, got %v", err)
	}
	if n < wire.HeaderLen+5 {
		t.Fatalf("refusal too short: %d", n)
	}
	// IIN2 is at offset HeaderLen + 4 (transport + AC + FC + IIN1)
	iin2 := buf[wire.HeaderLen+4]
	if iin2&0x04 == 0 {
		t.Fatalf("expected IIN2 FUNC_NOT_SUPP bit; got 0x%02x", iin2)
	}
}

func TestWriteWithAllowForwards(t *testing.T) {
	conn := driveSession(t, []dnpwrite.AllowedAppFunction{{FC: dnpwrite.AppFCWrite}})
	msg := buildUserDataFrame(dnpwrite.AppFCWrite)
	_ = conn.SetDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	_, err := conn.Read(buf)
	if err == nil {
		t.Fatal("expected no refusal for allowed Write")
	}
}

func TestDirectOperateRefusedByDefault(t *testing.T) {
	conn := driveSession(t, nil)
	msg := buildUserDataFrame(dnpwrite.AppFCDirectOperate)
	_ = conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("expected refusal, got %v", err)
	}
	if n < wire.HeaderLen {
		t.Fatalf("refusal too short: %d", n)
	}
}

func TestHandle_RequiresAuthorise(t *testing.T) {
	h := &dnpwrite.WriteGatedHandler{Target: "x", Deriver: &fakeDeriver{}, Auditor: &fakeAuditor{}}
	cr, _ := io.Pipe()
	rw := struct {
		io.Reader
		io.Writer
	}{cr, io.Discard}
	err := h.Handle(context.Background(), rw, rw)
	if !errors.Is(err, dnpwrite.ErrSessionNotAuthorised) {
		t.Fatalf("want ErrSessionNotAuthorised, got %v", err)
	}
}
