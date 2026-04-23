//go:build offensive

package bacnet_test

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"local/elsereno/internal/protocols/bacnet/wire"
	"local/elsereno/offensive/confirm"
	bwrite "local/elsereno/offensive/write/bacnet"
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

func mintToken(t *testing.T, target string, allowed []bwrite.AllowedService) string {
	t.Helper()
	mut := bwrite.SessionMutation(target, allowed)
	tok, err := confirm.ExpectedToken(mut, &fakeDeriver{key: []byte(testDeriverKey)})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func newHandler(t *testing.T, target string, allowed []bwrite.AllowedService) *bwrite.WriteGatedHandler {
	t.Helper()
	h := &bwrite.WriteGatedHandler{
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

// datagramRecorder captures every distinct datagram written.
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

// driveSession wires client ↔ handler ↔ upstream via net.Pipe
// pairs. The test holds `clientIn` (writes frames, reads
// refusals). Upstream frames go to upstreamRec.
func driveSession(t *testing.T, allowed []bwrite.AllowedService) (net.Conn, *datagramRecorder) {
	t.Helper()
	target := "bms.test:47808"
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

	rec := &datagramRecorder{}
	go rec.run(upstreamSide)
	go func() { _ = h.Handle(ctx, handlerClientSide, handlerUpstreamSide) }()

	return clientIn, rec
}

// buildBACnetFrame wraps an APDU payload in a BVLC + NPDU header
// suitable for the gate to parse. No routing fields (control
// byte = 0x04 expect-reply for confirmed requests).
func buildBACnetFrame(apdu []byte) []byte {
	npdu := []byte{0x01, 0x04}
	body := append([]byte{}, npdu...)
	body = append(body, apdu...)
	total := uint16(4 + len(body)) //nolint:gosec // len(body) ≤ a few dozen bytes by test construction
	return append([]byte{
		0x81,
		wire.BVLCOriginalUnicast,
		byte(total >> 8),
		byte(total & 0xFF),
	}, body...)
}

// buildConfirmedRequestAPDU builds a minimal confirmed-request
// APDU with the given service choice + invoke id. Body is
// empty — the gate only inspects header bytes.
func buildConfirmedRequestAPDU(svc wire.ConfirmedService, invokeID uint8) []byte {
	return []byte{
		byte(wire.APDUConfirmedRequest) << 4,
		0x05, // max-seg << 4 | max-resp
		invokeID,
		byte(svc),
	}
}

// buildUnconfirmedRequestAPDU builds an unconfirmed-request
// APDU (Who-Is = service choice 8).
func buildUnconfirmedRequestAPDU(svc uint8) []byte {
	return []byte{
		byte(wire.APDUUnconfirmedRequest) << 4,
		svc,
	}
}

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
	a := []bwrite.AllowedService{
		{ServiceChoice: uint8(wire.ConfirmedSvcWriteProperty)},
		{ServiceChoice: uint8(wire.ConfirmedSvcReinitializeDevice)},
	}
	b := []bwrite.AllowedService{
		{ServiceChoice: uint8(wire.ConfirmedSvcReinitializeDevice)},
		{ServiceChoice: uint8(wire.ConfirmedSvcWriteProperty)},
	}
	if bwrite.AllowlistHash("t", a) != bwrite.AllowlistHash("t", b) {
		t.Fatal("hash depends on input order")
	}
}

// ---- Authorise ------------------------------------------------

func TestAuthorise_HappyPath(t *testing.T) {
	target := "bms.test:47808"
	allowed := []bwrite.AllowedService{{ServiceChoice: uint8(wire.ConfirmedSvcWriteProperty)}}
	_ = newHandler(t, target, allowed)
}

func TestAuthorise_DeniedBadToken(t *testing.T) {
	target := "bms.test:47808"
	h := &bwrite.WriteGatedHandler{
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
	h := &bwrite.WriteGatedHandler{
		Target:  "bms.test:47808",
		Deriver: &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor: &fakeAuditor{},
	}
	if err := h.Handle(context.Background(), &ioPair{}, &ioPair{}); err == nil {
		t.Fatal("expected ErrSessionNotAuthorised")
	}
}

type ioPair struct{}

func (*ioPair) Read(_ []byte) (int, error)  { return 0, io.EOF }
func (*ioPair) Write(b []byte) (int, error) { return len(b), nil }

// ---- Routing: unconfirmed always passes -----------------------

func TestWhoIsAlwaysPasses(t *testing.T) {
	client, upstream := driveSession(t, nil)
	// Unconfirmed service 8 = Who-Is.
	apdu := buildUnconfirmedRequestAPDU(8)
	_, _ = client.Write(buildBACnetFrame(apdu))
	frames := waitForFramesOne(t, upstream)
	if len(frames[0]) < 4 || frames[0][0] != 0x81 {
		t.Fatalf("upstream did not see BVLC-framed Who-Is: % x", frames[0])
	}
}

func TestReadPropertyAlwaysPasses(t *testing.T) {
	client, upstream := driveSession(t, nil)
	// Confirmed ReadProperty (choice 12) — non-mutating.
	apdu := buildConfirmedRequestAPDU(wire.ConfirmedSvcReadProperty, 42)
	_, _ = client.Write(buildBACnetFrame(apdu))
	frames := waitForFramesOne(t, upstream)
	if len(frames[0]) < 10 {
		t.Fatalf("upstream did not see ReadProperty: % x", frames[0])
	}
}

func TestNonBACnetPassesThrough(t *testing.T) {
	client, upstream := driveSession(t, nil)
	// Garbage bytes (not starting with 0x81) pass through
	// — the gate refuses to second-guess unknown upper layers.
	_, _ = client.Write([]byte{0xAA, 0xBB, 0xCC, 0xDD})
	frames := waitForFramesOne(t, upstream)
	if len(frames[0]) != 4 || frames[0][0] != 0xAA {
		t.Fatalf("upstream did not see non-BACnet bytes verbatim: % x", frames[0])
	}
}

// ---- Routing: gated services ----------------------------------

func TestWritePropertyAllowedWithExplicitAllowlist(t *testing.T) {
	allowed := []bwrite.AllowedService{{ServiceChoice: uint8(wire.ConfirmedSvcWriteProperty)}}
	client, upstream := driveSession(t, allowed)
	apdu := buildConfirmedRequestAPDU(wire.ConfirmedSvcWriteProperty, 7)
	_, _ = client.Write(buildBACnetFrame(apdu))
	frames := waitForFramesOne(t, upstream)
	// The last byte of the APDU is the service choice; find it
	// in the forwarded frame.
	if frames[0][len(frames[0])-1] != byte(wire.ConfirmedSvcWriteProperty) {
		t.Fatalf("forwarded frame missing WriteProperty service byte: % x", frames[0])
	}
}

func TestWritePropertyBlockedReturnsAbort(t *testing.T) {
	client, upstream := driveSession(t, nil) // empty allowlist
	invokeID := uint8(13)
	apdu := buildConfirmedRequestAPDU(wire.ConfirmedSvcWriteProperty, invokeID)
	_, _ = client.Write(buildBACnetFrame(apdu))

	// Client should receive an Abort PDU back.
	_ = client.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 32)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("read Abort back: %v", err)
	}
	// BVLC prefix.
	if n < 4+2+3 {
		t.Fatalf("refusal too short: %d bytes", n)
	}
	if buf[0] != 0x81 || buf[1] != wire.BVLCOriginalUnicast {
		t.Fatalf("refusal BVLC prefix wrong: % x", buf[:2])
	}
	// Abort PDU lives right after BVLC(4) + NPDU(2).
	apduStart := 4 + 2
	if wire.APDUType(buf[apduStart]>>4) != wire.APDUAbort {
		t.Fatalf("expected APDUAbort, got type 0x%x", buf[apduStart]>>4)
	}
	if buf[apduStart+1] != invokeID {
		t.Fatalf("Abort invoke-id %d, want %d", buf[apduStart+1], invokeID)
	}
	if buf[apduStart+2] != bwrite.AbortReasonSecurity {
		t.Fatalf("Abort reason %d, want %d", buf[apduStart+2], bwrite.AbortReasonSecurity)
	}
	// Upstream should NOT have seen anything.
	time.Sleep(50 * time.Millisecond)
	if got := upstream.snapshot(); len(got) != 0 {
		t.Fatalf("upstream saw %d datagrams for a blocked WriteProperty", len(got))
	}
}

func TestReinitializeDeviceBlocked(t *testing.T) {
	// Allow only WriteProperty — ReinitializeDevice is a
	// different gated service and must be refused.
	allowed := []bwrite.AllowedService{{ServiceChoice: uint8(wire.ConfirmedSvcWriteProperty)}}
	client, upstream := driveSession(t, allowed)
	apdu := buildConfirmedRequestAPDU(wire.ConfirmedSvcReinitializeDevice, 99)
	_, _ = client.Write(buildBACnetFrame(apdu))

	_ = client.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 32)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("read Abort back: %v", err)
	}
	if n < 4+2+3 {
		t.Fatalf("refusal too short: %d bytes", n)
	}
	apduStart := 4 + 2
	if wire.APDUType(buf[apduStart]>>4) != wire.APDUAbort {
		t.Fatalf("expected APDUAbort for ReinitializeDevice, got 0x%x", buf[apduStart]>>4)
	}
	time.Sleep(50 * time.Millisecond)
	if got := upstream.snapshot(); len(got) != 0 {
		t.Fatalf("upstream saw %d datagrams for blocked ReinitializeDevice", len(got))
	}
}

func TestIsMutatingConfirmedService_Table(t *testing.T) {
	// Sanity-check the enum classification.
	cases := []struct {
		svc      wire.ConfirmedService
		mutating bool
	}{
		{wire.ConfirmedSvcReadProperty, false},
		{wire.ConfirmedSvcReadPropertyMultiple, false},
		{wire.ConfirmedSvcReadRange, false},
		{wire.ConfirmedSvcSubscribeCOV, false},
		{wire.ConfirmedSvcWriteProperty, true},
		{wire.ConfirmedSvcWritePropertyMultiple, true},
		{wire.ConfirmedSvcAtomicWriteFile, true},
		{wire.ConfirmedSvcCreateObject, true},
		{wire.ConfirmedSvcDeleteObject, true},
		{wire.ConfirmedSvcReinitializeDevice, true},
		{wire.ConfirmedSvcDeviceCommControl, true},
		{wire.ConfirmedSvcLifeSafetyOperation, true},
	}
	for _, c := range cases {
		if got := wire.IsMutatingConfirmedService(c.svc); got != c.mutating {
			t.Errorf("IsMutatingConfirmedService(%d) = %v, want %v", c.svc, got, c.mutating)
		}
	}
}
