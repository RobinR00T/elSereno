//go:build offensive

package dnp3_test

import (
	"bytes"
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

// buildUserDataFrame crafts a DNP3 user-data frame (dest 1, src 2)
// with the given app-layer FC and a single placeholder object byte.
func buildUserDataFrame(appFC uint8) []byte {
	return buildFrame(0x0001, 0x0002, appFC, []byte{0x00})
}

// buildFrame crafts a correct DNP3 unconfirmed-user-data frame
// (control 0xC4) with proper header + per-block CRCs. dest/src are the
// link addresses; objects are the app-layer object bytes after the FC.
func buildFrame(dest, src uint16, appFC uint8, objects []byte) []byte {
	return buildCtrlFrame(0xC4, dest, src, append([]byte{0xC0, 0xC0, appFC}, objects...))
}

// buildCtrlFrame crafts a frame with any control octet carrying
// userData, header and block CRCs correct.
func buildCtrlFrame(ctrl uint8, dest, src uint16, userData []byte) []byte {
	body := wire.AppendBlockCRCs(userData)
	frame := make([]byte, wire.HeaderLen+len(body))
	frame[0] = wire.StartBytes[0]
	frame[1] = wire.StartBytes[1]
	frame[2] = uint8(5 + len(userData)) // #nosec G115 -- test body fixed-size
	frame[3] = ctrl
	binary.LittleEndian.PutUint16(frame[4:6], dest)
	binary.LittleEndian.PutUint16(frame[6:8], src)
	crc := wire.CRC16(frame[0:8])
	binary.LittleEndian.PutUint16(frame[8:10], crc)
	copy(frame[wire.HeaderLen:], body)
	return frame
}

func mintToken(t *testing.T, target string, a dnpwrite.Allowlist) string {
	t.Helper()
	mut := dnpwrite.SessionMutation(target, a)
	tok, err := confirm.ExpectedToken(mut, &fakeDeriver{key: []byte("test-key-32-byte-long--------")})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func driveSession(t *testing.T, allowedApp []dnpwrite.AllowedAppFunction) net.Conn {
	t.Helper()
	client, upstream := startGate(t, allowedApp)
	go func() { _, _ = io.Copy(io.Discard, upstream) }()
	return client
}

// startGate runs an authorised gate between two pipes and returns the
// master's end and the outstation's end.
func startGate(t *testing.T, allowedApp []dnpwrite.AllowedAppFunction) (client, upstream net.Conn) {
	t.Helper()
	target := "127.0.0.1:20000"
	// The link-layer allowlist stays nil across the test matrix: the
	// gate's default policy accepts Confirmed + Unconfirmed User Data,
	// and the app-layer allowlist is what every test needs to vary.
	al := dnpwrite.Allowlist{AppFC: allowedApp}
	h := &dnpwrite.WriteGatedHandler{
		Target:       target,
		AllowedAppFC: allowedApp,
		Deriver:      &fakeDeriver{key: []byte("test-key-32-byte-long--------")},
		Auditor:      &fakeAuditor{},
		SessionConfirm: confirm.Confirm{
			AcceptsWrites: true,
			ConfirmTarget: target,
			ConfirmToken:  mintToken(t, target, al),
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
	go func() {
		_ = h.Handle(ctx, handlerClientSide, upstreamWriter)
	}()
	return clientPipe, upstreamReader
}

// TestGate_ResyncAndBadBlockCRC: a header with a bad CRC is skipped (the
// gate hunts for the next valid header instead of trusting its LENGTH),
// and a user-data frame with a bad block CRC is discarded without a reply
// (until 2026-10-14 the gate answered it with a refusal). The valid Read
// that follows both still passes.
func TestGate_ResyncAndBadBlockCRC(t *testing.T) {
	client, upstream := startGate(t, nil)
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	_ = upstream.SetDeadline(time.Now().Add(2 * time.Second))
	read := buildUserDataFrame(dnpwrite.AppFCRead)
	got := make(chan []byte, 1)
	go func() {
		buf := make([]byte, len(read))
		if _, err := io.ReadFull(upstream, buf); err == nil {
			got <- buf
		}
	}()
	badHdr := buildUserDataFrame(dnpwrite.AppFCRead)
	badHdr[8] ^= 0x01
	badBlock := buildUserDataFrame(dnpwrite.AppFCRead)
	badBlock[len(badBlock)-1] ^= 0x01
	if _, err := client.Write(append(append(badHdr, badBlock...), read...)); err != nil {
		t.Fatalf("client write: %v", err)
	}
	select {
	case f := <-got:
		if !bytes.Equal(f, read) {
			t.Fatalf("upstream got % x, want only the valid Read % x", f, read)
		}
	case <-time.After(time.Second):
		t.Fatal("the valid Read after a bad header and a bad block CRC did not arrive")
	}
	_ = client.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if n, err := client.Read(make([]byte, 64)); err == nil {
		t.Fatalf("the gate answered a discarded frame with %d octets", n)
	}
}

// TestGate_SecondaryFrameCarryingDataDiscarded: until 2026-10-14 the
// gate passed every PRM=0 frame, and the link functions 0, 2 and 9,
// with their body and before any of its four layers, so a Direct
// Operate TRIP wrapped in one reached the outstation with an empty
// allowlist (PITF-081). They are discarded now, without a reply, and
// the next valid frame still passes.
func TestGate_SecondaryFrameCarryingDataDiscarded(t *testing.T) {
	trip := append([]byte{0xC0, 0xC0, dnpwrite.AppFCDirectOperate},
		0x0C, 0x01, 0x17, 0x01, 0x07,
		0x81, 0x01, 0x64, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00)
	for _, ctrl := range []uint8{0x84, 0x04, 0x8B, 0xC9, 0xD2, 0xC0} {
		client, upstream := startGate(t, nil)
		_ = client.SetDeadline(time.Now().Add(2 * time.Second))
		_ = upstream.SetDeadline(time.Now().Add(2 * time.Second))
		read := buildUserDataFrame(dnpwrite.AppFCRead)
		got := make(chan []byte, 1)
		go func() {
			buf := make([]byte, len(read))
			if _, err := io.ReadFull(upstream, buf); err == nil {
				got <- buf
			}
		}()
		if _, err := client.Write(buildCtrlFrame(ctrl, 0x0001, 0x0002, trip)); err != nil {
			t.Fatalf("ctrl 0x%02x: client write: %v", ctrl, err)
		}
		select {
		case f := <-got:
			t.Fatalf("ctrl 0x%02x: the frame carrying a Direct Operate reached the outstation: % x", ctrl, f)
		case <-time.After(100 * time.Millisecond):
		}
		if _, err := client.Write(read); err != nil {
			t.Fatalf("ctrl 0x%02x: client write after the discarded frame: %v", ctrl, err)
		}
		select {
		case f := <-got:
			if !bytes.Equal(f, read) {
				t.Fatalf("ctrl 0x%02x: upstream got % x, want only the Read (the Direct Operate must never arrive)", ctrl, f)
			}
		case <-time.After(time.Second):
			t.Fatalf("ctrl 0x%02x: the Read after a discarded frame did not arrive", ctrl)
		}
	}
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
