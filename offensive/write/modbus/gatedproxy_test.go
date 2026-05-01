//go:build offensive

package modbus

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/hkdf"

	mbwire "local/elsereno/internal/protocols/modbus/wire"
	"local/elsereno/offensive/confirm"
	"local/elsereno/offensive/replay"
)

type stubDeriver2 struct{ master []byte }

func (s *stubDeriver2) Derive(info string, out []byte) error {
	r := hkdf.New(sha256.New, s.master, nil, []byte(info))
	_, err := io.ReadFull(r, out)
	return err
}

type captureAudit struct{ events []confirm.AuditEvent }

func (c *captureAudit) Record(_ context.Context, ev confirm.AuditEvent) error {
	c.events = append(c.events, ev)
	return nil
}

func TestAllowlistHash_Deterministic(t *testing.T) {
	target := "10.0.0.1:502"
	a := []AllowedWrite{
		{Unit: 1, FC: mbwire.FCWriteSingleCoil, StartAddr: 0, EndAddr: 100},
		{Unit: 2, FC: mbwire.FCWriteSingleRegister},
	}
	b := []AllowedWrite{
		// Same entries, different order.
		{Unit: 2, FC: mbwire.FCWriteSingleRegister},
		{Unit: 1, FC: mbwire.FCWriteSingleCoil, StartAddr: 0, EndAddr: 100},
	}
	if AllowlistHash(target, a) != AllowlistHash(target, b) {
		t.Fatal("AllowlistHash must be order-insensitive")
	}
}

func TestAllowlistHash_DifferentTarget(t *testing.T) {
	a := []AllowedWrite{{Unit: 1, FC: mbwire.FCWriteSingleCoil}}
	if AllowlistHash("10.0.0.1:502", a) == AllowlistHash("10.0.0.2:502", a) {
		t.Fatal("target must be bound into the hash")
	}
}

// buildGatedHandler returns a handler pre-authorised with a valid
// session token so Handle() can run.
func buildGatedHandler(t *testing.T, target string, allowed []AllowedWrite) (*WriteGatedHandler, *captureAudit) {
	t.Helper()
	d := &stubDeriver2{master: []byte("k")}
	a := &captureAudit{}
	m := SessionMutation(target, allowed)
	tok, err := confirm.ExpectedToken(m, d)
	if err != nil {
		t.Fatal(err)
	}
	h := &WriteGatedHandler{
		Target:  target,
		Allowed: allowed,
		Deriver: d,
		Auditor: a,
		SessionConfirm: confirm.Confirm{
			AcceptsWrites: true,
			ConfirmTarget: target,
			ConfirmToken:  tok,
		},
	}
	if err := h.Authorise(context.Background()); err != nil {
		t.Fatalf("Authorise: %v", err)
	}
	return h, a
}

func TestAuthorise_HappyPath(t *testing.T) {
	allowed := []AllowedWrite{{Unit: 1, FC: mbwire.FCWriteSingleRegister}}
	_, a := buildGatedHandler(t, "10.0.0.1:502", allowed)
	if len(a.events) != 1 || a.events[0].EventType != "offensive_allowed" {
		t.Fatalf("expected one offensive_allowed event, got %+v", a.events)
	}
	if a.events[0].Operation != "proxy_session" {
		t.Fatalf("operation: %q", a.events[0].Operation)
	}
}

func TestAuthorise_DeniedWithoutToken(t *testing.T) {
	h := &WriteGatedHandler{
		Target:  "10.0.0.1:502",
		Allowed: []AllowedWrite{},
		Deriver: &stubDeriver2{master: []byte("k")},
		Auditor: &captureAudit{},
		// No SessionConfirm flags set.
	}
	err := h.Authorise(context.Background())
	if !errors.Is(err, confirm.ErrNotAccepted) {
		t.Fatalf("expected ErrNotAccepted, got %v", err)
	}
}

func TestHandle_RequiresAuthorise(t *testing.T) {
	h := &WriteGatedHandler{}
	client, _ := net.Pipe()
	defer func() { _ = client.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	err := h.Handle(ctx, nil, nil)
	if !errors.Is(err, ErrSessionNotAuthorised) {
		t.Fatalf("expected ErrSessionNotAuthorised, got %v", err)
	}
}

// --- wire-level forwarding tests (via net.Pipe + helper) ---

func newPipePair() (client, clientSide, upstream, upstreamSide net.Conn) {
	client, clientSide = net.Pipe()
	upstream, upstreamSide = net.Pipe()
	return
}

func readFullFrame(r io.Reader) (mbwire.Frame, error) {
	return mbwire.ReadFrame(r)
}

func writeSingleRegister(addr, value uint16) mbwire.Frame {
	pdu := []byte{
		byte(mbwire.FCWriteSingleRegister),
		byte(addr >> 8), byte(addr & 0xFF),
		byte(value >> 8), byte(value & 0xFF),
	}
	return mbwire.Frame{
		MBAP: mbwire.MBAP{TxID: 1, Protocol: mbwire.ProtocolID, Unit: 1},
		PDU:  pdu,
	}
}

func readCoils(start uint16) mbwire.Frame {
	pdu := []byte{
		byte(mbwire.FCReadCoils),
		byte(start >> 8), byte(start & 0xFF),
		0x00, 0x01,
	}
	return mbwire.Frame{
		MBAP: mbwire.MBAP{TxID: 2, Protocol: mbwire.ProtocolID, Unit: 1},
		PDU:  pdu,
	}
}

func TestHandle_AllowedWriteForwards(t *testing.T) {
	t.Parallel()
	allowed := []AllowedWrite{
		{Unit: 1, FC: mbwire.FCWriteSingleRegister, StartAddr: 0, EndAddr: 0x100},
	}
	h, _ := buildGatedHandler(t, "target:502", allowed)

	client, clientSide, upstream, upstreamSide := newPipePair()
	defer func() { _ = client.Close() }()
	defer func() { _ = upstream.Close() }()
	defer func() { _ = clientSide.Close() }()
	defer func() { _ = upstreamSide.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() { _ = h.Handle(ctx, clientSide, upstreamSide) }()

	// Upstream should see the write byte-for-byte.
	got := make(chan mbwire.Frame, 1)
	go func() {
		f, err := readFullFrame(upstream)
		if err == nil {
			got <- f
		}
	}()
	req := writeSingleRegister(0x0010, 0x0042)
	if err := mbwire.WriteFrame(client, req); err != nil {
		t.Fatal(err)
	}
	select {
	case f := <-got:
		if !bytes.Equal(f.PDU, req.PDU) {
			t.Fatalf("upstream PDU differs: got % x want % x", f.PDU, req.PDU)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("upstream did not receive allowed write")
	}
}

func TestHandle_OutOfRangeWriteRefused(t *testing.T) {
	t.Parallel()
	allowed := []AllowedWrite{
		{Unit: 1, FC: mbwire.FCWriteSingleRegister, StartAddr: 0x0100, EndAddr: 0x0200},
	}
	h, _ := buildGatedHandler(t, "target:502", allowed)

	client, clientSide, upstream, upstreamSide := newPipePair()
	defer func() { _ = client.Close() }()
	defer func() { _ = upstream.Close() }()
	defer func() { _ = clientSide.Close() }()
	defer func() { _ = upstreamSide.Close() }()

	upstreamSeen := make(chan struct{}, 1)
	go func() {
		if _, err := readFullFrame(upstream); err == nil {
			upstreamSeen <- struct{}{}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() { _ = h.Handle(ctx, clientSide, upstreamSide) }()

	// Address 0x0042 is outside [0x0100,0x0200].
	req := writeSingleRegister(0x0042, 0xBEEF)
	if err := mbwire.WriteFrame(client, req); err != nil {
		t.Fatal(err)
	}

	// Client should see an IllegalFunction exception.
	resp, err := readFullFrame(client)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	ec, ok := resp.ExceptionCode()
	if !ok || ec != mbwire.ExIllegalFunction {
		t.Fatalf("expected IllegalFunction, got ok=%v ec=0x%02x", ok, ec)
	}

	// Upstream must NOT have seen the frame.
	select {
	case <-upstreamSeen:
		t.Fatal("out-of-range write reached upstream")
	case <-time.After(150 * time.Millisecond):
	}
}

func TestHandle_ReadForwardsRegardlessOfAllowlist(t *testing.T) {
	t.Parallel()
	// Empty allowlist — reads still forward.
	h, _ := buildGatedHandler(t, "target:502", nil)

	client, clientSide, upstream, upstreamSide := newPipePair()
	defer func() { _ = client.Close() }()
	defer func() { _ = upstream.Close() }()
	defer func() { _ = clientSide.Close() }()
	defer func() { _ = upstreamSide.Close() }()

	got := make(chan mbwire.Frame, 1)
	go func() {
		if f, err := readFullFrame(upstream); err == nil {
			got <- f
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() { _ = h.Handle(ctx, clientSide, upstreamSide) }()

	req := readCoils(0x0001)
	if err := mbwire.WriteFrame(client, req); err != nil {
		t.Fatal(err)
	}
	select {
	case f := <-got:
		if f.FunctionCode() != mbwire.FCReadCoils {
			t.Fatalf("wrong FC: 0x%02x", f.FunctionCode())
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("read never forwarded")
	}
}

func TestFrameAddr(t *testing.T) {
	t.Parallel()
	f := writeSingleRegister(0x1234, 0xBEEF)
	got, ok := frameAddr(f)
	if !ok || got != 0x1234 {
		t.Fatalf("frameAddr = (%d, %v), want (0x1234, true)", got, ok)
	}
	// Read FCs don't return an address via this helper.
	if _, ok := frameAddr(readCoils(1)); ok {
		t.Fatal("frameAddr unexpectedly returned ok for read FC")
	}
	// Short PDU: no address.
	short := mbwire.Frame{PDU: []byte{byte(mbwire.FCWriteSingleRegister)}}
	if _, ok := frameAddr(short); ok {
		t.Fatal("frameAddr ok on truncated PDU")
	}
	_ = binary.BigEndian // keep import
}

func TestAllowedWrite_UnitZeroMatchesAny(t *testing.T) {
	t.Parallel()
	a := AllowedWrite{Unit: 0, FC: mbwire.FCWriteSingleRegister}
	f1 := writeSingleRegister(0, 0)
	f1.MBAP.Unit = 1
	f2 := writeSingleRegister(0, 0)
	f2.MBAP.Unit = 99
	if !a.Matches(f1) || !a.Matches(f2) {
		t.Fatal("Unit=0 should match any unit")
	}
}

// TestHandle_RecordsBytesWhenRecorderSet — v1.30 chunk 1
// proves the optional Recorder field captures bytes that cross
// the wire-aware modbus gate. The wrap happens BEFORE the frame
// parser reads, so allowlist routing is preserved + the
// recording reflects what arrived from the client (not what
// the gate decided to forward, which is also valuable for
// post-mortems of refused frames).
func TestHandle_RecordsBytesWhenRecorderSet(t *testing.T) {
	target := "10.0.0.1:502"
	allowed := []AllowedWrite{{Unit: 1, FC: mbwire.FCWriteSingleRegister}}
	h, _ := buildGatedHandler(t, target, allowed)

	dir := t.TempDir()
	recPath := filepath.Join(dir, "session.ndjson")
	rec, err := replay.Open(recPath, "modbus", target)
	if err != nil {
		t.Fatalf("replay.Open: %v", err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	h.Recorder = rec

	clientPipe, handlerClient := net.Pipe()
	upstreamReader, handlerUpstream := net.Pipe()
	t.Cleanup(func() {
		_ = clientPipe.Close()
		_ = handlerClient.Close()
		_ = upstreamReader.Close()
		_ = handlerUpstream.Close()
	})

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = h.Handle(ctx, handlerClient, handlerUpstream) }()

	// Send one allowed write (FC=06 WriteSingleRegister, unit=1).
	frame := writeSingleRegister(0x0010, 0xBEEF)
	frame.MBAP.Unit = 1
	frame.MBAP.TxID = 1
	go func() {
		_ = mbwire.WriteFrame(clientPipe, frame)
	}()

	got := make([]byte, mbwire.MBAPLen+len(frame.PDU))
	_ = upstreamReader.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := upstreamReader.Read(got); err != nil {
		t.Fatalf("upstream read: %v", err)
	}

	// Close the recorder so the NDJSON is finalised before replay.
	if err := rec.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Permissions must be 0600 (operator-private capture).
	info, err := os.Stat(recPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Errorf("recording perms = %v, want no group/world bits", info.Mode().Perm())
	}

	// Header carries protocol="modbus" — distinguishes captures
	// across protocols when an operator has many recordings.
	hdr, err := replay.SeekHeader(recPath)
	if err != nil {
		t.Fatalf("SeekHeader: %v", err)
	}
	if hdr.Protocol != "modbus" {
		t.Errorf("recorded protocol = %q, want %q", hdr.Protocol, "modbus")
	}

	// At least one client→upstream chunk with the expected length.
	var sawClientToUpstream bool
	_ = replay.Replay(context.Background(), recPath, func(ev replay.ChunkEvent) error {
		if ev.Dir == replay.DirClientToUpstream && ev.Len > 0 {
			sawClientToUpstream = true
		}
		return nil
	})
	if !sawClientToUpstream {
		t.Errorf("recording did not capture a client_to_upstream chunk")
	}
}
