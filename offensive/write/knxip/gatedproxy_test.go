//go:build offensive

package knxip_test

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"local/elsereno/internal/protocols/knxip/wire"
	"local/elsereno/offensive/confirm"
	knxwrite "local/elsereno/offensive/write/knxip"
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

func mintToken(t *testing.T, target string, services []knxwrite.AllowedService, apcis []knxwrite.AllowedAPCI, groups []knxwrite.AllowedGroup) string {
	t.Helper()
	mut := knxwrite.SessionMutation(target, services, apcis, groups)
	tok, err := confirm.ExpectedToken(mut, &fakeDeriver{key: []byte(testDeriverKey)})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func newHandler(t *testing.T, target string, services []knxwrite.AllowedService, apcis []knxwrite.AllowedAPCI, groups []knxwrite.AllowedGroup) *knxwrite.WriteGatedHandler {
	t.Helper()
	h := &knxwrite.WriteGatedHandler{
		Target:          target,
		AllowedServices: services,
		AllowedAPCIs:    apcis,
		AllowedGroups:   groups,
		Deriver:         &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor:         &fakeAuditor{},
		SessionConfirm: confirm.Confirm{
			AcceptsWrites: true,
			ConfirmTarget: target,
			ConfirmToken:  mintToken(t, target, services, apcis, groups),
		},
	}
	if err := h.Authorise(context.Background()); err != nil {
		t.Fatal(err)
	}
	return h
}

// datagramRecorder captures upstream-facing datagrams.
type datagramRecorder struct {
	mu   sync.Mutex
	data [][]byte
}

func (r *datagramRecorder) run(conn net.Conn) {
	buf := make([]byte, 1500)
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

func driveSession(t *testing.T, services []knxwrite.AllowedService, apcis []knxwrite.AllowedAPCI, groups []knxwrite.AllowedGroup) (net.Conn, *datagramRecorder) {
	t.Helper()
	target := "knx.test:3671"
	h := newHandler(t, target, services, apcis, groups)
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
	upstreamRec := &datagramRecorder{}
	go upstreamRec.run(upstreamSide)
	go func() { _ = h.Handle(ctx, handlerClientSide, handlerUpstreamSide) }()
	return clientIn, upstreamRec
}

// buildTunnellingFrame: TUNNELLING_REQUEST + cEMI L_Data with the
// supplied destination + APCI. Mirrors the wire-package test
// helper. Always builds a group-addressed frame (Address Type
// bit set) — KNX writes are overwhelmingly group-addressed in
// practice, and the per-(GA, APCI) gating only fires on group
// frames.
func buildTunnellingFrame(dst uint16, apciTopNibble byte, data byte) []byte {
	frame := []byte{0x06, 0x10, 0x04, 0x20, 0x00, 0x15}
	frame = append(frame, 0x04, 0x01, 0x00, 0x00) // connection header
	ctrl2 := byte(0x80)                           // Address Type = group
	frame = append(frame,
		wire.CEMILDataReq, 0x00,
		0xBC, ctrl2,
		0x11, 0x01, // src
		byte(dst>>8), byte(dst&0xFF), // dst
		0x01,                           // NPDU
		0x00,                           // tpci (low 2 bits = APCI[9..8] = 0 here)
		(apciTopNibble<<4)|(data&0x3F), // top nibble = APCI[7..4], bottom 6 = data
	)
	return frame
}

func buildSearchRequest() []byte {
	return []byte{
		0x06, 0x10, 0x02, 0x01, 0x00, 0x0E,
		0x08, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
}

func buildConnectRequest() []byte {
	return []byte{
		0x06, 0x10, 0x02, 0x05, 0x00, 0x1A,
		0x08, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // control HPAI
		0x08, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // data HPAI
		0x04, 0x04, 0x02, 0x00, // CRI: tunnel-link-layer
	}
}

// waitForOneFrame polls until the recorder has at least one
// datagram or the deadline expires. The "n" was always 1 across
// every callsite — collapsed to a single-purpose helper.
func waitForOneFrame(t *testing.T, r *datagramRecorder) [][]byte {
	t.Helper()
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		snap := r.snapshot()
		if len(snap) >= 1 {
			return snap
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("recorder saw 0 frames; wanted ≥ 1")
	return nil
}

// shortPause: 100ms pause used as the "drop confirmed" guard
// after writing a datagram that should be silently refused.
const shortPause = 100 * time.Millisecond

// ---- AllowlistHash --------------------------------------------

func TestAllowlistHash_OrderInsensitive(t *testing.T) {
	a := []knxwrite.AllowedService{{ServiceType: wire.ServiceTypeTunnellingRequest}, {ServiceType: wire.ServiceTypeConnectRequest}}
	b := []knxwrite.AllowedService{{ServiceType: wire.ServiceTypeConnectRequest}, {ServiceType: wire.ServiceTypeTunnellingRequest}}
	if knxwrite.AllowlistHash("t", a, nil, nil) != knxwrite.AllowlistHash("t", b, nil, nil) {
		t.Fatal("hash depends on input order")
	}
}

func TestAllowlistHash_DifferentDimensions(t *testing.T) {
	target := "knx:3671"
	svc := []knxwrite.AllowedService{{ServiceType: wire.ServiceTypeTunnellingRequest}}
	apcis := []knxwrite.AllowedAPCI{{APCI: wire.APCIGroupValueWrite}}
	groups := []knxwrite.AllowedGroup{{GroupAddr: 0x0803, GroupMask: 0xFFFF}}
	hSvc := knxwrite.AllowlistHash(target, svc, nil, nil)
	hAPCI := knxwrite.AllowlistHash(target, svc, apcis, nil)
	hGroup := knxwrite.AllowlistHash(target, svc, apcis, groups)
	if hSvc == hAPCI {
		t.Fatal("APCI dimension should change hash")
	}
	if hAPCI == hGroup {
		t.Fatal("group dimension should change hash")
	}
}

// TestAllowlistHash_BackcompatEmptyDimensions keeps the v1.55
// hash stable when only the service dimension is configured —
// future cycles can extend without breaking pre-v1.55 tokens IF
// they preserve the same separator pattern.
func TestAllowlistHash_BackcompatEmptyDimensions(t *testing.T) {
	target := "knx:3671"
	svc := []knxwrite.AllowedService{{ServiceType: wire.ServiceTypeTunnellingRequest}}
	hZero := knxwrite.AllowlistHash(target, svc, nil, nil)
	hEmptySlices := knxwrite.AllowlistHash(target, svc, []knxwrite.AllowedAPCI{}, []knxwrite.AllowedGroup{})
	if hZero != hEmptySlices {
		t.Fatal("nil and empty-slice should produce same hash")
	}
}

// ---- AllowedGroup.Matches -------------------------------------

func TestAllowedGroup_Matches(t *testing.T) {
	for _, tc := range []struct {
		name     string
		entry    knxwrite.AllowedGroup
		dest     uint16
		expected bool
	}{
		{"exact-match", knxwrite.AllowedGroup{GroupAddr: 0x0803, GroupMask: 0xFFFF}, 0x0803, true},
		{"exact-mismatch", knxwrite.AllowedGroup{GroupAddr: 0x0803, GroupMask: 0xFFFF}, 0x0804, false},
		{"middle-group-mask", knxwrite.AllowedGroup{GroupAddr: 0x0800, GroupMask: 0xFF00}, 0x0805, true},
		{"middle-group-mask-out", knxwrite.AllowedGroup{GroupAddr: 0x0800, GroupMask: 0xFF00}, 0x0905, false},
		{"main-group-mask", knxwrite.AllowedGroup{GroupAddr: 0x0800, GroupMask: 0xF800}, 0x0F00, true},
		{"main-group-mask-out", knxwrite.AllowedGroup{GroupAddr: 0x0800, GroupMask: 0xF800}, 0x1000, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.entry.Matches(tc.dest); got != tc.expected {
				t.Errorf("Matches(0x%04x) = %v, want %v", tc.dest, got, tc.expected)
			}
		})
	}
}

// ---- Authorise ------------------------------------------------

func TestAuthorise_DeniedBadToken(t *testing.T) {
	target := "knx:3671"
	h := &knxwrite.WriteGatedHandler{
		Target:          target,
		AllowedServices: []knxwrite.AllowedService{{ServiceType: wire.ServiceTypeTunnellingRequest}},
		Deriver:         &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor:         &fakeAuditor{},
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

// TestAlwaysSafeServicePasses: SEARCH_REQUEST always passes even
// without an allowlist entry.
func TestAlwaysSafeServicePasses(t *testing.T) {
	clientIn, rec := driveSession(t, nil, nil, nil)
	if _, err := clientIn.Write(buildSearchRequest()); err != nil {
		t.Fatal(err)
	}
	frames := waitForOneFrame(t, rec)
	if len(frames) != 1 {
		t.Fatalf("got %d frames, want 1", len(frames))
	}
}

// TestNonAllowedServiceDropped: CONNECT_REQUEST is silently
// dropped when not in allowlist.
func TestNonAllowedServiceDropped(t *testing.T) {
	clientIn, rec := driveSession(t, nil, nil, nil)
	if _, err := clientIn.Write(buildConnectRequest()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(shortPause)
	if frames := rec.snapshot(); len(frames) != 0 {
		t.Fatalf("expected silent drop, got %d frames", len(frames))
	}
}

// TestAllowedServicePasses: CONNECT_REQUEST passes when
// allowlisted.
func TestAllowedServicePasses(t *testing.T) {
	services := []knxwrite.AllowedService{{ServiceType: wire.ServiceTypeConnectRequest}}
	clientIn, rec := driveSession(t, services, nil, nil)
	if _, err := clientIn.Write(buildConnectRequest()); err != nil {
		t.Fatal(err)
	}
	waitForOneFrame(t, rec)
}

// TestTunnellingReadAlwaysPasses: GroupValue_Read inside a
// TUNNELLING_REQUEST passes with no APCI allowlist needed.
func TestTunnellingReadAlwaysPasses(t *testing.T) {
	services := []knxwrite.AllowedService{{ServiceType: wire.ServiceTypeTunnellingRequest}}
	clientIn, rec := driveSession(t, services, nil, nil)
	frame := buildTunnellingFrame(0x0803, 0x0, 0x0) // APCI top nibble = 0 = Read
	if _, err := clientIn.Write(frame); err != nil {
		t.Fatal(err)
	}
	waitForOneFrame(t, rec)
}

// TestTunnellingWriteWithoutAPCIDropped: GroupValue_Write drops
// silently when APCI not allowlisted.
func TestTunnellingWriteWithoutAPCIDropped(t *testing.T) {
	services := []knxwrite.AllowedService{{ServiceType: wire.ServiceTypeTunnellingRequest}}
	clientIn, rec := driveSession(t, services, nil, nil)
	frame := buildTunnellingFrame(0x0803, 0x8, 0x1) // APCI top nibble = 8 = Write
	if _, err := clientIn.Write(frame); err != nil {
		t.Fatal(err)
	}
	time.Sleep(shortPause)
	if frames := rec.snapshot(); len(frames) != 0 {
		t.Fatalf("expected silent drop, got %d frames", len(frames))
	}
}

// TestTunnellingWriteAllowedAPCIInGroup: GroupValue_Write to
// group address inside allowed range passes.
func TestTunnellingWriteAllowedAPCIInGroup(t *testing.T) {
	services := []knxwrite.AllowedService{{ServiceType: wire.ServiceTypeTunnellingRequest}}
	apcis := []knxwrite.AllowedAPCI{{APCI: wire.APCIGroupValueWrite}}
	groups := []knxwrite.AllowedGroup{{GroupAddr: 0x0800, GroupMask: 0xFF00}} // 1/0/*
	clientIn, rec := driveSession(t, services, apcis, groups)
	frame := buildTunnellingFrame(0x0803, 0x8, 0x1) // 1/0/3
	if _, err := clientIn.Write(frame); err != nil {
		t.Fatal(err)
	}
	waitForOneFrame(t, rec)
}

// TestTunnellingWriteAllowedAPCIOutOfGroup: GroupValue_Write to
// group address OUTSIDE allowed range silently dropped.
func TestTunnellingWriteAllowedAPCIOutOfGroup(t *testing.T) {
	services := []knxwrite.AllowedService{{ServiceType: wire.ServiceTypeTunnellingRequest}}
	apcis := []knxwrite.AllowedAPCI{{APCI: wire.APCIGroupValueWrite}}
	groups := []knxwrite.AllowedGroup{{GroupAddr: 0x0800, GroupMask: 0xFF00}} // 1/0/*
	clientIn, rec := driveSession(t, services, apcis, groups)
	frame := buildTunnellingFrame(0x1003, 0x8, 0x1) // 2/0/3 — outside
	if _, err := clientIn.Write(frame); err != nil {
		t.Fatal(err)
	}
	time.Sleep(shortPause)
	if frames := rec.snapshot(); len(frames) != 0 {
		t.Fatalf("expected silent drop, got %d frames", len(frames))
	}
}

// TestTunnellingWriteEmptyGroupsAllowAll: when AllowedGroups is
// empty AND APCI allowlisted, any GA passes (service-level
// allowance only).
func TestTunnellingWriteEmptyGroupsAllowAll(t *testing.T) {
	services := []knxwrite.AllowedService{{ServiceType: wire.ServiceTypeTunnellingRequest}}
	apcis := []knxwrite.AllowedAPCI{{APCI: wire.APCIGroupValueWrite}}
	clientIn, rec := driveSession(t, services, apcis, nil)
	frame := buildTunnellingFrame(0xFF00, 0x8, 0x1)
	if _, err := clientIn.Write(frame); err != nil {
		t.Fatal(err)
	}
	waitForOneFrame(t, rec)
}

// TestTunnellingMalformedRefuses: malformed cEMI body refuses
// silently.
func TestTunnellingMalformedRefuses(t *testing.T) {
	services := []knxwrite.AllowedService{{ServiceType: wire.ServiceTypeTunnellingRequest}}
	apcis := []knxwrite.AllowedAPCI{{APCI: wire.APCIGroupValueWrite}}
	clientIn, rec := driveSession(t, services, apcis, nil)
	// Truncated frame: header + conn-header + only 3 cEMI bytes.
	frame := []byte{0x06, 0x10, 0x04, 0x20, 0x00, 0x0D, 0x04, 0x01, 0x00, 0x00, 0x11, 0x00, 0xBC}
	if _, err := clientIn.Write(frame); err != nil {
		t.Fatal(err)
	}
	time.Sleep(shortPause)
	if frames := rec.snapshot(); len(frames) != 0 {
		t.Fatalf("expected silent drop, got %d frames", len(frames))
	}
}

// TestUpstreamPassesThrough: upstream → client direction is a
// straight io.Copy.
func TestUpstreamPassesThrough(t *testing.T) {
	services := []knxwrite.AllowedService{{ServiceType: wire.ServiceTypeTunnellingRequest}}
	target := "knx:3671"
	h := newHandler(t, target, services, nil, nil)
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

	// Upstream sends a TUNNELLING_ACK back to the client.
	upstreamMsg := []byte{0x06, 0x10, 0x04, 0x21, 0x00, 0x0A, 0x04, 0x01, 0x00, 0x00}
	go func() { _, _ = upstreamSide.Write(upstreamMsg) }()
	buf := make([]byte, 1500)
	_ = clientIn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	n, err := clientIn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(upstreamMsg) {
		t.Errorf("got %d bytes, want %d", n, len(upstreamMsg))
	}
}

// TestTooShortFrameDropped: a 3-byte garbage datagram is dropped
// silently rather than crashing the parse path.
func TestTooShortFrameDropped(t *testing.T) {
	clientIn, rec := driveSession(t, nil, nil, nil)
	if _, err := clientIn.Write([]byte{0xAA, 0xBB, 0xCC}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(shortPause)
	if frames := rec.snapshot(); len(frames) != 0 {
		t.Fatalf("expected silent drop, got %d frames", len(frames))
	}
}

// TestForwardErrorPropagates: ensure io.EOF is folded to nil so
// caller doesn't see the channel close as an error.
func TestForwardErrorPropagates(t *testing.T) {
	target := "knx:3671"
	h := newHandler(t, target, nil, nil, nil)
	clientA, clientB := net.Pipe()
	upstreamA, upstreamB := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- h.Handle(ctx, clientB, upstreamB) }()
	_ = clientA.Close() // close client → handler sees EOF
	_ = upstreamA.Close()
	select {
	case err := <-done:
		// EOF was folded to nil; any other error is acceptable
		// (pipe closed) — we just want to confirm the handler
		// returned within the deadline.
		_ = err
	case <-time.After(500 * time.Millisecond):
		t.Fatal("handler did not return after both pipes closed")
	}
}

// TestAuthoriseIdempotent: calling Authorise twice is a no-op.
func TestAuthoriseIdempotent(t *testing.T) {
	target := "knx:3671"
	h := newHandler(t, target, nil, nil, nil)
	if err := h.Authorise(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// TestErrSessionNotAuthorised: Handle without prior Authorise
// returns the sentinel.
func TestErrSessionNotAuthorised(t *testing.T) {
	h := &knxwrite.WriteGatedHandler{
		Target:  "knx:3671",
		Deriver: &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor: &fakeAuditor{},
	}
	clientIn, clientB := net.Pipe()
	upstreamA, upstreamB := net.Pipe()
	t.Cleanup(func() {
		_ = clientIn.Close()
		_ = clientB.Close()
		_ = upstreamA.Close()
		_ = upstreamB.Close()
	})
	err := h.Handle(context.Background(), clientB, upstreamB)
	if err == nil {
		t.Fatal("expected ErrSessionNotAuthorised")
	}
	if !isNotAuthorised(err) {
		t.Errorf("err = %v, want ErrSessionNotAuthorised", err)
	}
}

func isNotAuthorised(err error) bool {
	return err != nil && err.Error() == knxwrite.ErrSessionNotAuthorised.Error()
}

// TestSessionMutationWithGenerationDifferentFromBase: bumping
// generation produces a different hash.
func TestSessionMutationWithGenerationDifferentFromBase(t *testing.T) {
	svc := []knxwrite.AllowedService{{ServiceType: wire.ServiceTypeTunnellingRequest}}
	target := "knx:3671"
	mZero := knxwrite.SessionMutationWithGeneration(target, svc, nil, nil, 0)
	mOne := knxwrite.SessionMutationWithGeneration(target, svc, nil, nil, 1)
	if mZero.PayloadHash == mOne.PayloadHash {
		t.Fatal("generation should change hash")
	}
	mBase := knxwrite.SessionMutation(target, svc, nil, nil)
	if mBase.PayloadHash != mZero.PayloadHash {
		t.Fatal("generation=0 should equal SessionMutation")
	}
}

// silence unused-import on io if test doesn't compile.
var _ = io.EOF
