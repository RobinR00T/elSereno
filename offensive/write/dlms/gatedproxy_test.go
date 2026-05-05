//go:build offensive

package dlms_test

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	dlmswire "local/elsereno/internal/protocols/dlms/wire"
	"local/elsereno/offensive/confirm"
	dlmswrite "local/elsereno/offensive/write/dlms"
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

func mintToken(t *testing.T, target string, apdus []dlmswrite.AllowedAPDU, cosems []dlmswrite.AllowedCosem) string {
	t.Helper()
	mut := dlmswrite.SessionMutation(target, apdus, cosems)
	tok, err := confirm.ExpectedToken(mut, &fakeDeriver{key: []byte(testDeriverKey)})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func newHandler(t *testing.T, target string, apdus []dlmswrite.AllowedAPDU, cosems []dlmswrite.AllowedCosem) *dlmswrite.WriteGatedHandler {
	t.Helper()
	h := &dlmswrite.WriteGatedHandler{
		Target:        target,
		AllowedAPDUs:  apdus,
		AllowedCosems: cosems,
		Deriver:       &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor:       &fakeAuditor{},
		SessionConfirm: confirm.Confirm{
			AcceptsWrites: true,
			ConfirmTarget: target,
			ConfirmToken:  mintToken(t, target, apdus, cosems),
		},
	}
	if err := h.Authorise(context.Background()); err != nil {
		t.Fatal(err)
	}
	return h
}

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

func driveSession(t *testing.T, apdus []dlmswrite.AllowedAPDU, cosems []dlmswrite.AllowedCosem) (net.Conn, *upstreamRecorder) {
	t.Helper()
	target := "meter.test:4059"
	h := newHandler(t, target, apdus, cosems)
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

func wrapAPDU(apdu []byte) []byte {
	frame := make([]byte, dlmswire.WrapperLen+len(apdu))
	binary.BigEndian.PutUint16(frame[0:2], dlmswire.WrapperVersion)
	binary.BigEndian.PutUint16(frame[2:4], dlmswire.SourceWPortClient)
	binary.BigEndian.PutUint16(frame[4:6], dlmswire.DestWPortServer)
	if len(apdu) > 0xFFFF {
		panic("apdu too long")
	}
	// #nosec G115 -- length range-checked above
	binary.BigEndian.PutUint16(frame[6:8], uint16(len(apdu)))
	copy(frame[dlmswire.WrapperLen:], apdu)
	return frame
}

func setAPDU(classID uint16, obis [6]byte, attr byte) []byte {
	apdu := []byte{
		dlmswire.APDUTagSetRequest, 0x01, 0xC1,
		byte(classID >> 8), byte(classID & 0xFF),
	}
	apdu = append(apdu, obis[:]...)
	apdu = append(apdu, attr, 0x00, 0x09, 0x01, 0xAA)
	return apdu
}

func actionAPDU(classID uint16, obis [6]byte, method byte) []byte {
	apdu := []byte{
		dlmswire.APDUTagActionRequest, 0x01, 0xC1,
		byte(classID >> 8), byte(classID & 0xFF),
	}
	apdu = append(apdu, obis[:]...)
	apdu = append(apdu, method, 0x00)
	return apdu
}

func aarqAPDU() []byte {
	return []byte{dlmswire.APDUTagAARQ, 0x05, 0xA1, 0x03, 0x06, 0x01, 0x00}
}

func getAPDU() []byte {
	return []byte{dlmswire.APDUTagGetRequest, 0x01, 0xC1, 0x00, 0x03,
		0, 0, 96, 1, 0, 255, 2, 0}
}

const shortPause = 100 * time.Millisecond

// ---- AllowedCosem.Matches -------------------------------------

func TestAllowedCosem_Matches(t *testing.T) {
	disconnect := [6]byte{0, 0, 96, 50, 0, 255}
	for _, tc := range []struct {
		name     string
		entry    dlmswrite.AllowedCosem
		target   dlmswire.CosemTarget
		expected bool
	}{
		{"exact-match",
			dlmswrite.AllowedCosem{ClassID: 70, OBIS: disconnect, MemberID: 1, MatchType: dlmswrite.MatchExact},
			dlmswire.CosemTarget{ClassID: 70, OBIS: disconnect, MemberID: 1},
			true},
		{"exact-class-mismatch",
			dlmswrite.AllowedCosem{ClassID: 70, OBIS: disconnect, MemberID: 1, MatchType: dlmswrite.MatchExact},
			dlmswire.CosemTarget{ClassID: 71, OBIS: disconnect, MemberID: 1},
			false},
		{"exact-obis-mismatch",
			dlmswrite.AllowedCosem{ClassID: 70, OBIS: disconnect, MemberID: 1, MatchType: dlmswrite.MatchExact},
			dlmswire.CosemTarget{ClassID: 70, OBIS: [6]byte{0, 0, 96, 51, 0, 255}, MemberID: 1},
			false},
		{"exact-member-mismatch",
			dlmswrite.AllowedCosem{ClassID: 70, OBIS: disconnect, MemberID: 1, MatchType: dlmswrite.MatchExact},
			dlmswire.CosemTarget{ClassID: 70, OBIS: disconnect, MemberID: 2},
			false},
		{"class-obis-wildcards-member",
			dlmswrite.AllowedCosem{ClassID: 70, OBIS: disconnect, MatchType: dlmswrite.MatchClassOBIS},
			dlmswire.CosemTarget{ClassID: 70, OBIS: disconnect, MemberID: 99},
			true},
		{"class-only-wildcards-everything",
			dlmswrite.AllowedCosem{ClassID: 70, MatchType: dlmswrite.MatchClassOnly},
			dlmswire.CosemTarget{ClassID: 70, OBIS: [6]byte{1, 2, 3, 4, 5, 6}, MemberID: 7},
			true},
		{"obis-byte-wildcard",
			dlmswrite.AllowedCosem{ClassID: 70, OBIS: [6]byte{0, 0, 96, 0xFF, 0xFF, 0xFF}, MemberID: 1, MatchType: dlmswrite.MatchExact},
			dlmswire.CosemTarget{ClassID: 70, OBIS: [6]byte{0, 0, 96, 50, 0, 255}, MemberID: 1},
			true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.entry.Matches(tc.target); got != tc.expected {
				t.Errorf("got %v, want %v", got, tc.expected)
			}
		})
	}
}

// ---- AllowlistHash --------------------------------------------

func TestAllowlistHash_OrderInsensitive(t *testing.T) {
	apdusA := []dlmswrite.AllowedAPDU{{Tag: dlmswire.APDUTagSetRequest}, {Tag: dlmswire.APDUTagActionRequest}}
	apdusB := []dlmswrite.AllowedAPDU{{Tag: dlmswire.APDUTagActionRequest}, {Tag: dlmswire.APDUTagSetRequest}}
	if dlmswrite.AllowlistHash("t", apdusA, nil) != dlmswrite.AllowlistHash("t", apdusB, nil) {
		t.Fatal("hash depends on input order")
	}
}

func TestAllowlistHash_EmptyCosemsStable(t *testing.T) {
	apdus := []dlmswrite.AllowedAPDU{{Tag: dlmswire.APDUTagSetRequest}}
	hZero := dlmswrite.AllowlistHash("t", apdus, nil)
	hEmpty := dlmswrite.AllowlistHash("t", apdus, []dlmswrite.AllowedCosem{})
	if hZero != hEmpty {
		t.Fatal("nil and empty-slice cosems should hash equal")
	}
}

func TestAllowlistHash_DifferentCosemDimensions(t *testing.T) {
	disconnect := [6]byte{0, 0, 96, 50, 0, 255}
	apdus := []dlmswrite.AllowedAPDU{{Tag: dlmswire.APDUTagSetRequest}}
	hAPDUOnly := dlmswrite.AllowlistHash("t", apdus, nil)
	hWithCosem := dlmswrite.AllowlistHash("t", apdus, []dlmswrite.AllowedCosem{{ClassID: 70, OBIS: disconnect, MemberID: 1, MatchType: dlmswrite.MatchExact}})
	if hAPDUOnly == hWithCosem {
		t.Fatal("cosem dimension should change hash")
	}
}

func TestSessionMutationWithGeneration_Differs(t *testing.T) {
	apdus := []dlmswrite.AllowedAPDU{{Tag: dlmswire.APDUTagSetRequest}}
	target := "t:4059"
	mZero := dlmswrite.SessionMutationWithGeneration(target, apdus, nil, 0)
	mOne := dlmswrite.SessionMutationWithGeneration(target, apdus, nil, 1)
	if mZero.PayloadHash == mOne.PayloadHash {
		t.Fatal("generation should change hash")
	}
}

// ---- Authorise ------------------------------------------------

func TestAuthorise_DeniedBadToken(t *testing.T) {
	target := "t:4059"
	h := &dlmswrite.WriteGatedHandler{
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

// ---- routing decisions ----------------------------------------

func TestAARQPassesUnconditional(t *testing.T) {
	clientIn, rec := driveSession(t, nil, nil)
	frame := wrapAPDU(aarqAPDU())
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

func TestGetRequestPasses(t *testing.T) {
	clientIn, rec := driveSession(t, nil, nil)
	frame := wrapAPDU(getAPDU())
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

func TestSetRequestNoTagDropped(t *testing.T) {
	clientIn, rec := driveSession(t, nil, nil)
	disconnect := [6]byte{0, 0, 96, 50, 0, 255}
	frame := wrapAPDU(setAPDU(70, disconnect, 1))
	if _, err := clientIn.Write(frame); err != nil {
		t.Fatal(err)
	}
	time.Sleep(shortPause)
	if got := rec.snapshot(); len(got) != 0 {
		t.Fatalf("expected silent drop, got %d bytes", len(got))
	}
}

func TestSetRequestTagButNoCosemDropped(t *testing.T) {
	apdus := []dlmswrite.AllowedAPDU{{Tag: dlmswire.APDUTagSetRequest}}
	clientIn, rec := driveSession(t, apdus, nil)
	disconnect := [6]byte{0, 0, 96, 50, 0, 255}
	frame := wrapAPDU(setAPDU(70, disconnect, 1))
	if _, err := clientIn.Write(frame); err != nil {
		t.Fatal(err)
	}
	time.Sleep(shortPause)
	if got := rec.snapshot(); len(got) != 0 {
		t.Fatalf("expected silent drop, got %d bytes", len(got))
	}
}

func TestSetRequestExactMatchPasses(t *testing.T) {
	apdus := []dlmswrite.AllowedAPDU{{Tag: dlmswire.APDUTagSetRequest}}
	disconnect := [6]byte{0, 0, 96, 50, 0, 255}
	cosems := []dlmswrite.AllowedCosem{{ClassID: 70, OBIS: disconnect, MemberID: 1, MatchType: dlmswrite.MatchExact}}
	clientIn, rec := driveSession(t, apdus, cosems)
	frame := wrapAPDU(setAPDU(70, disconnect, 1))
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

func TestSetRequestClassOnlyMatchPasses(t *testing.T) {
	apdus := []dlmswrite.AllowedAPDU{{Tag: dlmswire.APDUTagSetRequest}}
	cosems := []dlmswrite.AllowedCosem{{ClassID: 3, MatchType: dlmswrite.MatchClassOnly}}
	clientIn, rec := driveSession(t, apdus, cosems)
	tariffOBIS := [6]byte{1, 0, 94, 7, 0, 255}
	frame := wrapAPDU(setAPDU(3, tariffOBIS, 2))
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

func TestActionRequestNotAllowedDropped(t *testing.T) {
	apdus := []dlmswrite.AllowedAPDU{{Tag: dlmswire.APDUTagSetRequest}}
	clientIn, rec := driveSession(t, apdus, nil)
	disconnect := [6]byte{0, 0, 96, 50, 0, 255}
	frame := wrapAPDU(actionAPDU(70, disconnect, 2))
	if _, err := clientIn.Write(frame); err != nil {
		t.Fatal(err)
	}
	time.Sleep(shortPause)
	if got := rec.snapshot(); len(got) != 0 {
		t.Fatalf("expected silent drop, got %d bytes", len(got))
	}
}

func TestActionRequestAllowedPasses(t *testing.T) {
	apdus := []dlmswrite.AllowedAPDU{{Tag: dlmswire.APDUTagActionRequest}}
	disconnect := [6]byte{0, 0, 96, 50, 0, 255}
	cosems := []dlmswrite.AllowedCosem{{ClassID: 70, OBIS: disconnect, MatchType: dlmswrite.MatchClassOBIS}}
	clientIn, rec := driveSession(t, apdus, cosems)
	frame := wrapAPDU(actionAPDU(70, disconnect, 2))
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

func TestSetRequestObisWildcardPasses(t *testing.T) {
	apdus := []dlmswrite.AllowedAPDU{{Tag: dlmswire.APDUTagSetRequest}}
	cosems := []dlmswrite.AllowedCosem{{ClassID: 70, OBIS: [6]byte{0, 0, 96, 0xFF, 0xFF, 0xFF}, MemberID: 0, MatchType: dlmswrite.MatchClassOBIS}}
	clientIn, rec := driveSession(t, apdus, cosems)
	frame := wrapAPDU(setAPDU(70, [6]byte{0, 0, 96, 50, 0, 255}, 2))
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

func TestErrSessionNotAuthorised(t *testing.T) {
	h := &dlmswrite.WriteGatedHandler{
		Target:  "t:4059",
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
	if err.Error() != dlmswrite.ErrSessionNotAuthorised.Error() {
		t.Errorf("err = %v, want %v", err, dlmswrite.ErrSessionNotAuthorised)
	}
}

// silence unused import on io
var _ = io.EOF
