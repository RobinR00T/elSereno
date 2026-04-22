//go:build offensive

package opcua_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"local/elsereno/internal/protocols/opcua/wire"
	"local/elsereno/offensive/confirm"
	opwrite "local/elsereno/offensive/write/opcua"
)

// ---- fakes ----------------------------------------------------

type fakeDeriver struct{ key []byte }

func (f *fakeDeriver) Derive(_ string, out []byte) error {
	copy(out, f.key)
	return nil
}

type fakeAuditor struct{ events []confirm.AuditEvent }

func (f *fakeAuditor) Record(_ context.Context, ev confirm.AuditEvent) error {
	f.events = append(f.events, ev)
	return nil
}

// buildMSG crafts a minimal MSG chunk containing a FourByteNodeId
// TypeId + zero payload. Enough to exercise the service-routing
// path without bringing in a full UA request encoder.
func buildMSG(typeID uint16) []byte {
	body := make([]byte, 0, 24)
	// SecureChannelId, TokenId, SequenceNumber, RequestId — all 0.
	body = append(body, make([]byte, 16)...)
	// FourByteNodeId encoding.
	body = append(body, byte(wire.NodeIDFourByte), 0x00)
	var tid [2]byte
	binary.LittleEndian.PutUint16(tid[:], typeID)
	body = append(body, tid[:]...)
	// Wrap as MSG chunk.
	total := wire.HeaderSize + len(body)
	frame := make([]byte, total)
	copy(frame[0:3], "MSG")
	frame[3] = byte(wire.ChunkFinal)
	// #nosec G115 — total is bounded by the test's hand-rolled body
	binary.LittleEndian.PutUint32(frame[4:8], uint32(total))
	copy(frame[wire.HeaderSize:], body)
	return frame
}

// mintToken mints the triple-confirm token so the handler's
// Authorise passes.
func mintToken(t *testing.T, target string, allowed []opwrite.AllowedService) string {
	t.Helper()
	mut := opwrite.SessionMutation(target, allowed)
	tok, err := confirm.ExpectedToken(mut, &fakeDeriver{key: []byte("test-key-32-byte-long--------")})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// driveSession wires a real net.Pipe pair between client and
// the handler, authorises, starts Handle in a goroutine, and
// returns the client-side connection. Cleanup is installed via
// t.Cleanup so the caller never needs to cancel manually.
func driveSession(t *testing.T, allowed []opwrite.AllowedService) net.Conn {
	t.Helper()
	target := "127.0.0.1:14840"
	deriver := &fakeDeriver{key: []byte("test-key-32-byte-long--------")}
	auditor := &fakeAuditor{}
	h := &opwrite.WriteGatedHandler{
		Target:  target,
		Allowed: allowed,
		Deriver: deriver,
		Auditor: auditor,
		SessionConfirm: confirm.Confirm{
			AcceptsWrites: true,
			ConfirmTarget: target,
			ConfirmToken:  mintToken(t, target, allowed),
		},
	}
	if err := h.Authorise(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Client <-> handler pipe
	clientPipe, handlerClientSide := net.Pipe()
	// Upstream: discard writes, never read.
	upstreamReader, upstreamWriter := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = clientPipe.Close()
		_ = handlerClientSide.Close()
		_ = upstreamReader.Close()
		_ = upstreamWriter.Close()
	})
	// Drain upstream to /dev/null in the background so blocked
	// writes don't deadlock the handler.
	go func() { _, _ = io.Copy(io.Discard, upstreamReader) }()
	go func() {
		// The client side of the handler pipe + writer-side of
		// upstream pipe form the handler's two endpoints.
		_ = h.Handle(ctx, handlerClientSide, upstreamWriter)
	}()
	return clientPipe
}

// ---- AllowlistHash deterministic ------------------------------

func TestAllowlistHash_OrderInsensitive(t *testing.T) {
	a := []opwrite.AllowedService{{TypeID: wire.TypeIDWriteRequest}, {TypeID: wire.TypeIDCallRequest}}
	b := []opwrite.AllowedService{{TypeID: wire.TypeIDCallRequest}, {TypeID: wire.TypeIDWriteRequest}}
	hashA := opwrite.AllowlistHash("t", a)
	hashB := opwrite.AllowlistHash("t", b)
	if hashA != hashB {
		t.Fatalf("hash depends on input order: %x vs %x", hashA, hashB)
	}
}

func TestAllowlistHash_DifferentTarget(t *testing.T) {
	a := []opwrite.AllowedService{{TypeID: wire.TypeIDWriteRequest}}
	h1 := opwrite.AllowlistHash("host-a:4840", a)
	h2 := opwrite.AllowlistHash("host-b:4840", a)
	if h1 == h2 {
		t.Fatal("hash should vary with target")
	}
}

// ---- Authorise contract ---------------------------------------

func TestAuthorise_HappyPath(t *testing.T) {
	target := "127.0.0.1:4840"
	allowed := []opwrite.AllowedService{{TypeID: wire.TypeIDWriteRequest}}
	h := &opwrite.WriteGatedHandler{
		Target:  target,
		Allowed: allowed,
		Deriver: &fakeDeriver{key: []byte("test-key-32-byte-long--------")},
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
	// Second call is a no-op.
	if err := h.Authorise(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestAuthorise_DeniedWithoutToken(t *testing.T) {
	target := "127.0.0.1:4840"
	h := &opwrite.WriteGatedHandler{
		Target:  target,
		Deriver: &fakeDeriver{key: []byte("test-key-32-byte-long--------")},
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

// ---- Routing --------------------------------------------------

func TestRouting_HELPassesThrough(t *testing.T) {
	// HEL frames should never hit the allowlist; they're
	// transport-level.
	conn := driveSession(t, nil)

	// Build a minimal HEL frame (HEL header + 24+0 bytes body).
	hel := wire.EncodeHello(wire.Hello{
		ReceiveBufSize: 65536,
		SendBufSize:    65536,
		MaxMessageSize: 16777216,
		MaxChunkCount:  5000,
		EndpointURL:    "opc.tcp://x:4840/",
	})
	_ = conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := conn.Write(hel); err != nil {
		t.Fatalf("write HEL: %v", err)
	}
	// Read-side: handler returns control to client after copying,
	// but the upstream discard goroutine consumes the bytes so no
	// reply is expected back on `conn` for HEL alone. A 500ms
	// absence of ERR / refusal frame is the success signal.
	buf := make([]byte, 64)
	_, err := conn.Read(buf)
	if err == nil {
		t.Fatal("expected timeout/no-reply for bare HEL, got data")
	}
}

func TestRouting_ReadRequestAlwaysPasses(t *testing.T) {
	// Empty allowlist: reads still forward.
	conn := driveSession(t, nil)
	msg := buildMSG(wire.TypeIDReadRequest)
	_ = conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	_, err := conn.Read(buf)
	// Handler forwarded to upstream (discard); no refusal on client.
	if err == nil {
		t.Fatal("expected no refusal for ReadRequest, got data on client")
	}
}

func TestRouting_WriteWithEmptyAllowlistRefused(t *testing.T) {
	conn := driveSession(t, nil)
	msg := buildMSG(wire.TypeIDWriteRequest)
	_ = conn.SetDeadline(time.Now().Add(1 * time.Second))
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	// Refusal is a MSG ServiceFault with status
	// BadUserAccessDenied (0x80100000).
	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("expected refusal MSG, got error: %v", err)
	}
	if n < wire.HeaderSize {
		t.Fatalf("refusal too short: %d", n)
	}
	h, err := wire.ParseHeader(buf[:wire.HeaderSize])
	if err != nil {
		t.Fatal(err)
	}
	if h.Type != wire.MessageMessage {
		t.Fatalf("refusal type = %q", h.Type)
	}
	// Check the ServiceFault TypeId (397) is at the expected
	// offset in the body.
	if n < wire.HeaderSize+20 {
		t.Fatalf("refusal body too short for TypeId: %d", n)
	}
	if buf[wire.HeaderSize+16] != byte(wire.NodeIDFourByte) {
		t.Fatalf("refusal TypeId encoding = 0x%02x", buf[wire.HeaderSize+16])
	}
	gotTypeID := binary.LittleEndian.Uint16(buf[wire.HeaderSize+18 : wire.HeaderSize+20])
	if gotTypeID != 397 {
		t.Fatalf("refusal TypeId = %d, want 397 (ServiceFault)", gotTypeID)
	}
	// StatusCode lives at body offset 16 (4 headers × 4 bytes) +
	// 4 (FourByteNodeId = enc + ns + u16 id) + 8 (Timestamp) +
	// 4 (RequestHandle) = 32 → body[32:36].
	offStatus := wire.HeaderSize + 16 + 4 + 8 + 4
	if n < offStatus+4 {
		t.Fatalf("refusal body truncated before StatusCode")
	}
	status := binary.LittleEndian.Uint32(buf[offStatus : offStatus+4])
	if status != 0x80100000 {
		t.Fatalf("refusal StatusCode = 0x%08x, want 0x80100000", status)
	}
}

func TestRouting_WriteInAllowlistForwards(t *testing.T) {
	allowed := []opwrite.AllowedService{{TypeID: wire.TypeIDWriteRequest}}
	conn := driveSession(t, allowed)
	msg := buildMSG(wire.TypeIDWriteRequest)
	_ = conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	// Should forward upstream; no refusal on client.
	buf := make([]byte, 64)
	_, err := conn.Read(buf)
	if err == nil {
		t.Fatal("expected no refusal for allowed WriteRequest")
	}
}

func TestRouting_CallTreatedLikeWrite(t *testing.T) {
	// CallRequest (704) not in allowlist → refused.
	conn := driveSession(t, nil)
	msg := buildMSG(wire.TypeIDCallRequest)
	_ = conn.SetDeadline(time.Now().Add(1 * time.Second))
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("expected refusal, got %v", err)
	}
	if n < wire.HeaderSize {
		t.Fatalf("refusal too short")
	}
}

// ---- Handle precondition -------------------------------------

func TestHandle_RequiresAuthorise(t *testing.T) {
	h := &opwrite.WriteGatedHandler{
		Target:  "x",
		Deriver: &fakeDeriver{},
		Auditor: &fakeAuditor{},
	}
	cr, _ := io.Pipe()
	cw := &bytes.Buffer{}
	err := h.Handle(context.Background(),
		struct {
			io.Reader
			io.Writer
		}{cr, cw},
		&bytes.Buffer{},
	)
	if !errors.Is(err, opwrite.ErrSessionNotAuthorised) {
		t.Fatalf("want ErrSessionNotAuthorised, got %v", err)
	}
}
