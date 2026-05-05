//go:build offensive

package mbustcp_test

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	mbwire "local/elsereno/internal/protocols/mbustcp/wire"
	"local/elsereno/offensive/confirm"
	mbustcp "local/elsereno/offensive/write/mbustcp"
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

func mintToken(t *testing.T, target string, allowed []mbustcp.AllowedSNDUD) string {
	t.Helper()
	mut := mbustcp.SessionMutation(target, allowed)
	tok, err := confirm.ExpectedToken(mut, &fakeDeriver{key: []byte(testDeriverKey)})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func newHandler(t *testing.T, target string, allowed []mbustcp.AllowedSNDUD) *mbustcp.WriteGatedHandler {
	t.Helper()
	h := &mbustcp.WriteGatedHandler{
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

// upstreamRecorder captures bytes the handler forwards toward
// upstream. Net.Pipe preserves Write boundaries with bytes.Buffer
// semantics, so each handler-side Write surfaces as a Read on
// the recording side.
type upstreamRecorder struct {
	mu  sync.Mutex
	buf []byte
}

func (r *upstreamRecorder) run(conn net.Conn) {
	buf := make([]byte, 1500)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			r.mu.Lock()
			r.buf = append(r.buf, buf[:n]...)
			r.mu.Unlock()
		}
		if err != nil {
			return
		}
	}
}

func (r *upstreamRecorder) snapshot() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]byte, len(r.buf))
	copy(out, r.buf)
	return out
}

// driveSession wires client ↔ handler ↔ upstream via net.Pipe.
func driveSession(t *testing.T, allowed []mbustcp.AllowedSNDUD) (net.Conn, *upstreamRecorder) {
	t.Helper()
	target := "meter-gw.test:10001"
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
	rec := &upstreamRecorder{}
	go rec.run(upstreamSide)
	go func() { _ = h.Handle(ctx, handlerClientSide, handlerUpstreamSide) }()
	return clientIn, rec
}

// buildLong builds a long M-Bus frame with body C+A+CI+UD.
// control is parameterised to document intent across callsites,
// even though every test in this file currently uses ControlSNDUD.
//
//nolint:unparam // control documents intent; see comment above
func buildLong(control, address, ci byte, ud []byte) []byte {
	bodyLen := 3 + len(ud)
	if bodyLen > 255 {
		panic("buildLong: body too long for test fixture")
	}
	frame := make([]byte, 0, 4+bodyLen+2)
	// #nosec G115 -- bodyLen bound-checked above
	frame = append(frame, mbwire.StartLong, byte(bodyLen), byte(bodyLen), mbwire.StartLong)
	body := []byte{control, address, ci}
	body = append(body, ud...)
	var cs byte
	for _, b := range body {
		cs += b
	}
	frame = append(frame, body...)
	frame = append(frame, cs, mbwire.StopByte)
	return frame
}

// buildShort builds a 5-byte short M-Bus frame. address is
// parameterised to document intent across callsites, even though
// every test currently uses 0x05.
//
//nolint:unparam // address documents intent; see comment above
func buildShort(control, address byte) []byte {
	cs := control + address
	return []byte{mbwire.StartShort, control, address, cs, mbwire.StopByte}
}

// shortPause is the "drop confirmed" guard after writing a frame
// the gate is expected to refuse.
const shortPause = 100 * time.Millisecond

// ---- AllowedSNDUD.Matches ------------------------------------

func TestAllowedSNDUD_Matches(t *testing.T) {
	type row struct {
		name     string
		entry    mbustcp.AllowedSNDUD
		frame    mbwire.Frame
		expected bool
	}
	for _, tc := range []row{
		{"empty-matches-nothing",
			mbustcp.AllowedSNDUD{},
			mbwire.Frame{IsLong: true, Control: mbwire.ControlSNDUD, Address: 0x05, CI: mbwire.CIDataSend},
			false},
		{"exact-ci-and-addr",
			mbustcp.AllowedSNDUD{CI: mbwire.CIDataSend, Address: 0x05},
			mbwire.Frame{IsLong: true, Control: mbwire.ControlSNDUD, Address: 0x05, CI: mbwire.CIDataSend},
			true},
		{"ci-mismatch",
			mbustcp.AllowedSNDUD{CI: mbwire.CIDataSend, Address: 0x05},
			mbwire.Frame{IsLong: true, Control: mbwire.ControlSNDUD, Address: 0x05, CI: mbwire.CIAppReset},
			false},
		{"addr-mismatch",
			mbustcp.AllowedSNDUD{CI: mbwire.CIDataSend, Address: 0x05},
			mbwire.Frame{IsLong: true, Control: mbwire.ControlSNDUD, Address: 0x06, CI: mbwire.CIDataSend},
			false},
		{"ci-wildcard",
			mbustcp.AllowedSNDUD{Address: 0x05},
			mbwire.Frame{IsLong: true, Control: mbwire.ControlSNDUD, Address: 0x05, CI: mbwire.CIAppReset},
			true},
		{"addr-wildcard",
			mbustcp.AllowedSNDUD{CI: mbwire.CIDataSend},
			mbwire.Frame{IsLong: true, Control: mbwire.ControlSNDUD, Address: 0xFE, CI: mbwire.CIDataSend},
			true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.entry.Matches(tc.frame)
			if got != tc.expected {
				t.Errorf("got %v, want %v", got, tc.expected)
			}
		})
	}
}

// ---- AllowlistHash --------------------------------------------

func TestAllowlistHash_OrderInsensitive(t *testing.T) {
	a := []mbustcp.AllowedSNDUD{{CI: mbwire.CIDataSend, Address: 0x05}, {CI: mbwire.CIAppReset, Address: 0x06}}
	b := []mbustcp.AllowedSNDUD{{CI: mbwire.CIAppReset, Address: 0x06}, {CI: mbwire.CIDataSend, Address: 0x05}}
	if mbustcp.AllowlistHash("t", a) != mbustcp.AllowlistHash("t", b) {
		t.Fatal("hash depends on input order")
	}
}

func TestAllowlistHash_DifferentTarget(t *testing.T) {
	a := []mbustcp.AllowedSNDUD{{CI: mbwire.CIDataSend, Address: 0x05}}
	if mbustcp.AllowlistHash("a:10001", a) == mbustcp.AllowlistHash("b:10001", a) {
		t.Fatal("hash should vary with target")
	}
}

func TestAllowlistHash_DifferentEntries(t *testing.T) {
	target := "t:10001"
	a := []mbustcp.AllowedSNDUD{{CI: mbwire.CIDataSend, Address: 0x05}}
	b := []mbustcp.AllowedSNDUD{{CI: mbwire.CIDataSend, Address: 0x06}}
	if mbustcp.AllowlistHash(target, a) == mbustcp.AllowlistHash(target, b) {
		t.Fatal("hash should vary with allowlist contents")
	}
}

func TestSessionMutationWithGeneration_Differs(t *testing.T) {
	a := []mbustcp.AllowedSNDUD{{CI: mbwire.CIDataSend, Address: 0x05}}
	target := "t:10001"
	mZero := mbustcp.SessionMutationWithGeneration(target, a, 0)
	mOne := mbustcp.SessionMutationWithGeneration(target, a, 1)
	if mZero.PayloadHash == mOne.PayloadHash {
		t.Fatal("generation should change hash")
	}
	if mbustcp.SessionMutation(target, a).PayloadHash != mZero.PayloadHash {
		t.Fatal("generation=0 should match SessionMutation")
	}
}

// ---- Authorise ------------------------------------------------

func TestAuthorise_DeniedBadToken(t *testing.T) {
	target := "t:10001"
	h := &mbustcp.WriteGatedHandler{
		Target:  target,
		Deriver: &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor: &fakeAuditor{},
		SessionConfirm: confirm.Confirm{
			AcceptsWrites: true,
			ConfirmTarget: target,
			ConfirmToken:  "this-is-not-a-valid-token",
		},
	}
	if err := h.Authorise(context.Background()); err == nil {
		t.Fatal("expected Authorise to fail on bad token")
	}
}

// ---- forward routing ------------------------------------------

// TestREQUD2Passes: REQ_UD2 is always-safe (read).
func TestREQUD2Passes(t *testing.T) {
	clientIn, rec := driveSession(t, nil)
	frame := buildShort(mbwire.ControlREQUD2, 0x05)
	if _, err := clientIn.Write(frame); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if len(rec.snapshot()) >= len(frame) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := rec.snapshot(); len(got) != len(frame) {
		t.Fatalf("got %d bytes, want %d", len(got), len(frame))
	}
}

// TestSNDNKEPasses: SND_NKE link-reset is always-safe.
func TestSNDNKEPasses(t *testing.T) {
	clientIn, rec := driveSession(t, nil)
	frame := buildShort(mbwire.ControlSNDNKE, 0x05)
	if _, err := clientIn.Write(frame); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if len(rec.snapshot()) >= len(frame) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := rec.snapshot(); len(got) != len(frame) {
		t.Fatalf("got %d bytes, want %d", len(got), len(frame))
	}
}

// TestSNDUDNotAllowedDropped: SND_UD with no allowlist drops.
func TestSNDUDNotAllowedDropped(t *testing.T) {
	clientIn, rec := driveSession(t, nil)
	frame := buildLong(mbwire.ControlSNDUD, 0x05, mbwire.CIDataSend, []byte{0xAA, 0xBB})
	if _, err := clientIn.Write(frame); err != nil {
		t.Fatal(err)
	}
	time.Sleep(shortPause)
	if got := rec.snapshot(); len(got) != 0 {
		t.Fatalf("expected silent drop, got %d bytes", len(got))
	}
}

// TestSNDUDAllowedPasses: SND_UD with matching allowlist entry
// forwards.
func TestSNDUDAllowedPasses(t *testing.T) {
	allowed := []mbustcp.AllowedSNDUD{{CI: mbwire.CIDataSend, Address: 0x05}}
	clientIn, rec := driveSession(t, allowed)
	frame := buildLong(mbwire.ControlSNDUD, 0x05, mbwire.CIDataSend, []byte{0xAA, 0xBB})
	if _, err := clientIn.Write(frame); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if len(rec.snapshot()) >= len(frame) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := rec.snapshot(); len(got) != len(frame) {
		t.Fatalf("got %d bytes, want %d", len(got), len(frame))
	}
}

// TestSNDUDAllowedAddrMismatchDropped: SND_UD to wrong address
// drops despite the allowlist matching the CI byte.
func TestSNDUDAllowedAddrMismatchDropped(t *testing.T) {
	allowed := []mbustcp.AllowedSNDUD{{CI: mbwire.CIDataSend, Address: 0x05}}
	clientIn, rec := driveSession(t, allowed)
	frame := buildLong(mbwire.ControlSNDUD, 0x06, mbwire.CIDataSend, []byte{0xAA, 0xBB})
	if _, err := clientIn.Write(frame); err != nil {
		t.Fatal(err)
	}
	time.Sleep(shortPause)
	if got := rec.snapshot(); len(got) != 0 {
		t.Fatalf("expected silent drop, got %d bytes", len(got))
	}
}

// TestSNDUDAllowedCIMismatchDropped: SND_UD with wrong CI drops
// despite address matching.
func TestSNDUDAllowedCIMismatchDropped(t *testing.T) {
	allowed := []mbustcp.AllowedSNDUD{{CI: mbwire.CIDataSend, Address: 0x05}}
	clientIn, rec := driveSession(t, allowed)
	frame := buildLong(mbwire.ControlSNDUD, 0x05, mbwire.CISyncAction, []byte{0xAA})
	if _, err := clientIn.Write(frame); err != nil {
		t.Fatal(err)
	}
	time.Sleep(shortPause)
	if got := rec.snapshot(); len(got) != 0 {
		t.Fatalf("expected silent drop, got %d bytes", len(got))
	}
}

// TestSNDUDCIWildcard: AllowedSNDUD{Address: 0x05} matches any
// CI to that address.
func TestSNDUDCIWildcard(t *testing.T) {
	allowed := []mbustcp.AllowedSNDUD{{Address: 0x05}}
	clientIn, rec := driveSession(t, allowed)
	frame := buildLong(mbwire.ControlSNDUD, 0x05, mbwire.CIAppReset, nil)
	if _, err := clientIn.Write(frame); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if len(rec.snapshot()) >= len(frame) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := rec.snapshot(); len(got) != len(frame) {
		t.Fatalf("got %d bytes, want %d", len(got), len(frame))
	}
}

// TestUnknownControlDropped: a frame with an out-of-vocabulary
// control byte is refused (gate doesn't pass what it can't
// classify).
func TestUnknownControlDropped(t *testing.T) {
	clientIn, rec := driveSession(t, nil)
	// Control byte 0x00 isn't in the vocabulary.
	frame := buildShort(0x00, 0x05)
	if _, err := clientIn.Write(frame); err != nil {
		t.Fatal(err)
	}
	time.Sleep(shortPause)
	if got := rec.snapshot(); len(got) != 0 {
		t.Fatalf("expected silent drop, got %d bytes", len(got))
	}
}

// TestACKPasses: 0xE5 ACK from client side passes through.
func TestACKPasses(t *testing.T) {
	clientIn, rec := driveSession(t, nil)
	if _, err := clientIn.Write([]byte{mbwire.ACKByte}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if len(rec.snapshot()) >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := rec.snapshot(); len(got) != 1 {
		t.Fatalf("got %d bytes, want 1", len(got))
	}
}

// TestUpstreamPassesThrough: upstream → client is a straight
// io.Copy.
func TestUpstreamPassesThrough(t *testing.T) {
	target := "t:10001"
	h := newHandler(t, target, nil)
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
	go func() { _ = h.Handle(ctx, handlerClientSide, handlerUpstreamSide) }()
	upstreamMsg := buildShort(mbwire.ControlREQUD2, 0x05)
	go func() { _, _ = upstreamSide.Write(upstreamMsg) }()
	buf := make([]byte, 64)
	_ = clientIn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	n, err := clientIn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(upstreamMsg) {
		t.Errorf("got %d bytes, want %d", n, len(upstreamMsg))
	}
}

// TestErrSessionNotAuthorised returns the sentinel without a
// prior Authorise.
func TestErrSessionNotAuthorised(t *testing.T) {
	h := &mbustcp.WriteGatedHandler{
		Target:  "t:10001",
		Deriver: &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor: &fakeAuditor{},
	}
	clientA, clientB := net.Pipe()
	upstreamA, upstreamB := net.Pipe()
	t.Cleanup(func() {
		_ = clientA.Close()
		_ = clientB.Close()
		_ = upstreamA.Close()
		_ = upstreamB.Close()
	})
	err := h.Handle(context.Background(), clientB, upstreamB)
	if err == nil {
		t.Fatal("expected ErrSessionNotAuthorised")
	}
	if err.Error() != mbustcp.ErrSessionNotAuthorised.Error() {
		t.Errorf("err = %v, want %v", err, mbustcp.ErrSessionNotAuthorised)
	}
}

// silence unused-import on io
var _ = io.EOF
