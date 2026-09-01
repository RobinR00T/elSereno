//go:build offensive

package finsudp_test

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"local/elsereno/internal/protocols/finsudp/wire"
	"local/elsereno/offensive/confirm"
	finswrite "local/elsereno/offensive/write/finsudp"
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

func mintToken(t *testing.T, target string, allowed []finswrite.AllowedCommand, areas []finswrite.AllowedArea) string {
	t.Helper()
	mut := finswrite.SessionMutation(target, allowed, areas)
	tok, err := confirm.ExpectedToken(mut, &fakeDeriver{key: []byte(testDeriverKey)})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func newHandler(t *testing.T, target string, allowed []finswrite.AllowedCommand, areas []finswrite.AllowedArea) *finswrite.WriteGatedHandler {
	t.Helper()
	h := &finswrite.WriteGatedHandler{
		Target:       target,
		Allowed:      allowed,
		AllowedAreas: areas,
		Deriver:      &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor:      &fakeAuditor{},
		SessionConfirm: confirm.Confirm{
			AcceptsWrites: true,
			ConfirmTarget: target,
			ConfirmToken:  mintToken(t, target, allowed, areas),
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
	buf := make([]byte, wire.HeaderLen+512)
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

const testTarget = "fins.test:9600"

func driveSession(t *testing.T, allowed []finswrite.AllowedCommand, areas []finswrite.AllowedArea) (net.Conn, *datagramRecorder) {
	t.Helper()
	h := newHandler(t, testTarget, allowed, areas)
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

// buildFINS builds a FINS/UDP request frame: the 10-byte header
// (request ICF, SID 0x2A) + MRC + SRC + optional command data.
func buildFINS(mrc, src byte, data ...byte) []byte {
	frame := []byte{
		wire.ICFRequest, 0x00, 0x02, // ICF RSV GCT
		0x00, 0x00, 0x00, // DNA DA1 DA2
		0x00, 0x01, 0x00, // SNA SA1 SA2
		0x2A,     // SID
		mrc, src, // command
	}
	return append(frame, data...)
}

const shortPause = 100 * time.Millisecond

// readOne reads a single datagram from the client side with a
// deadline; used to capture the native refusal written back.
func readOne(t *testing.T, c net.Conn) []byte {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, wire.HeaderLen+16)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("expected a refusal datagram from the client side: %v", err)
	}
	return buf[:n]
}

func waitForOneFrame(t *testing.T, r *datagramRecorder) [][]byte {
	t.Helper()
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if snap := r.snapshot(); len(snap) >= 1 {
			return snap
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("recorder saw 0 frames; wanted >= 1")
	return nil
}

// ---- tests ----------------------------------------------------

func TestAllowlistHash_OrderInsensitive(t *testing.T) {
	a := []finswrite.AllowedCommand{{MRC: 0x01, SRC: 0x02}, {MRC: 0x04, SRC: 0x01}}
	b := []finswrite.AllowedCommand{{MRC: 0x04, SRC: 0x01}, {MRC: 0x01, SRC: 0x02}}
	if finswrite.AllowlistHash(testTarget, a, nil) != finswrite.AllowlistHash(testTarget, b, nil) {
		t.Fatal("AllowlistHash is order-sensitive")
	}
	// A different target must produce a different hash.
	if finswrite.AllowlistHash(testTarget, a, nil) == finswrite.AllowlistHash("other:9600", a, nil) {
		t.Fatal("AllowlistHash ignores the target")
	}
}

func TestAuthorise_DeniedBadToken(t *testing.T) {
	h := &finswrite.WriteGatedHandler{
		Target:  testTarget,
		Deriver: &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor: &fakeAuditor{},
		SessionConfirm: confirm.Confirm{
			AcceptsWrites: true,
			ConfirmTarget: testTarget,
			ConfirmToken:  "not-the-expected-token",
		},
	}
	if err := h.Authorise(context.Background()); err == nil {
		t.Fatal("Authorise accepted a bad token")
	}
}

func TestReadCommandPassesUpstream(t *testing.T) {
	// Empty allowlist: a read must still pass (reads can't mutate).
	client, rec := driveSession(t, nil, nil)
	req := buildFINS(0x01, 0x01) // Memory Area Read
	if _, err := client.Write(req); err != nil {
		t.Fatal(err)
	}
	got := waitForOneFrame(t, rec)
	if len(got[0]) != len(req) {
		t.Fatalf("forwarded %d bytes, want %d", len(got[0]), len(req))
	}
}

func TestAllowedWritePassesUpstream(t *testing.T) {
	allow := []finswrite.AllowedCommand{{MRC: 0x01, SRC: 0x02}} // Memory Area Write
	client, rec := driveSession(t, allow, nil)
	req := buildFINS(0x01, 0x02, 0xB0, 0x00, 0x64, 0x00, 0x00, 0x01, 0x12, 0x34)
	if _, err := client.Write(req); err != nil {
		t.Fatal(err)
	}
	got := waitForOneFrame(t, rec)
	if got[0][wire.HeaderLen] != 0x01 || got[0][wire.HeaderLen+1] != 0x02 {
		t.Fatalf("forwarded command = 0x%02x%02x, want 0x0102",
			got[0][wire.HeaderLen], got[0][wire.HeaderLen+1])
	}
}

// areaOffset is where the memory-area code sits in a Memory Area Write
// body (10-byte header + MRC + SRC).
const areaOffset = wire.HeaderLen + 2

func TestAreaScoping_AllowedAreaPasses(t *testing.T) {
	allow := []finswrite.AllowedCommand{{MRC: 0x01, SRC: 0x02}}
	areas := []finswrite.AllowedArea{{Area: 0x82}} // DM word
	client, rec := driveSession(t, allow, areas)
	req := buildFINS(0x01, 0x02, 0x82, 0x00, 0x64, 0x00, 0x00, 0x01, 0x12, 0x34)
	if _, err := client.Write(req); err != nil {
		t.Fatal(err)
	}
	got := waitForOneFrame(t, rec)
	if got[0][areaOffset] != 0x82 {
		t.Fatalf("forwarded area = 0x%02x, want 0x82", got[0][areaOffset])
	}
}

func TestAreaScoping_DisallowedAreaRefused(t *testing.T) {
	allow := []finswrite.AllowedCommand{{MRC: 0x01, SRC: 0x02}}
	areas := []finswrite.AllowedArea{{Area: 0x82}} // only DM word is allowed
	client, rec := driveSession(t, allow, areas)
	// Memory Area Write to CIO (0xB0): command allowlisted, area not.
	req := buildFINS(0x01, 0x02, 0xB0, 0x00, 0x00, 0x00, 0x00, 0x01, 0xFF, 0xFF)
	if _, err := client.Write(req); err != nil {
		t.Fatal(err)
	}
	ref := readOne(t, client)
	if ref[wire.HeaderLen+2] != 0x21 || ref[wire.HeaderLen+3] != 0x01 {
		t.Errorf("area-refusal end code = 0x%02x%02x, want 0x2101",
			ref[wire.HeaderLen+2], ref[wire.HeaderLen+3])
	}
	time.Sleep(shortPause)
	if snap := rec.snapshot(); len(snap) != 0 {
		t.Fatalf("a disallowed-area write leaked %d frame(s) upstream", len(snap))
	}
}

func TestAllowlistHash_AreasChangeToken(t *testing.T) {
	cmds := []finswrite.AllowedCommand{{MRC: 0x01, SRC: 0x02}}
	if finswrite.AllowlistHash(testTarget, cmds, nil) ==
		finswrite.AllowlistHash(testTarget, cmds, []finswrite.AllowedArea{{Area: 0x82}}) {
		t.Fatal("adding an area did not change the hash")
	}
	a1 := finswrite.AllowlistHash(testTarget, cmds, []finswrite.AllowedArea{{Area: 0x82}, {Area: 0xB0}})
	a2 := finswrite.AllowlistHash(testTarget, cmds, []finswrite.AllowedArea{{Area: 0xB0}, {Area: 0x82}})
	if a1 != a2 {
		t.Fatal("area hash is order-sensitive")
	}
}

func TestNonAllowedWriteRefused(t *testing.T) {
	// Empty allowlist: Memory Area Write must be refused, not forwarded.
	client, rec := driveSession(t, nil, nil)
	req := buildFINS(0x01, 0x02, 0xB0, 0x00, 0x00, 0x00, 0x00, 0x01, 0xFF, 0xFF)
	if _, err := client.Write(req); err != nil {
		t.Fatal(err)
	}
	// The client receives a native FINS refusal.
	ref := readOne(t, client)
	if len(ref) != wire.HeaderLen+4 {
		t.Fatalf("refusal length = %d, want %d", len(ref), wire.HeaderLen+4)
	}
	if ref[0]&0x40 == 0 {
		t.Errorf("refusal ICF 0x%02x lacks the response bit", ref[0])
	}
	if ref[wire.HeaderLen] != 0x01 || ref[wire.HeaderLen+1] != 0x02 {
		t.Errorf("refusal did not echo the MRC/SRC")
	}
	if ref[wire.HeaderLen+2] != 0x21 || ref[wire.HeaderLen+3] != 0x01 {
		t.Errorf("refusal end code = 0x%02x%02x, want 0x2101",
			ref[wire.HeaderLen+2], ref[wire.HeaderLen+3])
	}
	// Nothing must have reached upstream.
	time.Sleep(shortPause)
	if snap := rec.snapshot(); len(snap) != 0 {
		t.Fatalf("a refused write leaked %d frame(s) upstream", len(snap))
	}
}

func TestUnknownCommandRefused(t *testing.T) {
	client, rec := driveSession(t, []finswrite.AllowedCommand{{MRC: 0x01, SRC: 0x02}}, nil)
	// 0x99/0x99 is not in any table -> CategoryUnknown -> refuse,
	// even though an unrelated write command is allowlisted.
	req := buildFINS(0x99, 0x99)
	if _, err := client.Write(req); err != nil {
		t.Fatal(err)
	}
	ref := readOne(t, client)
	if ref[0]&0x40 == 0 {
		t.Errorf("unknown-command refusal lacks the response bit")
	}
	time.Sleep(shortPause)
	if snap := rec.snapshot(); len(snap) != 0 {
		t.Fatalf("an unknown command leaked %d frame(s) upstream", len(snap))
	}
}

func TestShortFrameRefused(t *testing.T) {
	client, rec := driveSession(t, nil, nil)
	// 6 bytes: too short to carry MRC/SRC -> refuse.
	if _, err := client.Write([]byte{0x80, 0x00, 0x02, 0x00, 0x00, 0x00}); err != nil {
		t.Fatal(err)
	}
	ref := readOne(t, client)
	if len(ref) != wire.HeaderLen+4 || ref[0]&0x40 == 0 {
		t.Fatalf("short-frame refusal malformed: len=%d icf=0x%02x", len(ref), ref[0])
	}
	time.Sleep(shortPause)
	if snap := rec.snapshot(); len(snap) != 0 {
		t.Fatalf("a short frame leaked %d frame(s) upstream", len(snap))
	}
}

func TestHandle_RequiresAuthorise(t *testing.T) {
	h := &finswrite.WriteGatedHandler{Target: testTarget}
	c1, c2 := net.Pipe()
	u1, u2 := net.Pipe()
	t.Cleanup(func() { _ = c1.Close(); _ = c2.Close(); _ = u1.Close(); _ = u2.Close() })
	err := h.Handle(context.Background(), c2, u1)
	if !errors.Is(err, finswrite.ErrSessionNotAuthorised) {
		t.Fatalf("Handle without Authorise returned %v, want ErrSessionNotAuthorised", err)
	}
}
