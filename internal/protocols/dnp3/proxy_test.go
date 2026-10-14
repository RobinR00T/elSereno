package dnp3_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"testing"
	"time"

	"local/elsereno/internal/protocols/dnp3"
	"local/elsereno/internal/protocols/dnp3/wire"
)

// buildFrame returns a minimal link-layer-only DNP3 frame with the
// given control byte and a correct header CRC (the proxy checks it).
func buildFrame(control uint8) []byte {
	f := []byte{
		wire.StartBytes[0], wire.StartBytes[1],
		0x05,       // length
		control,    // control
		0x00, 0x00, // dest
		0x01, 0x00, // src
		0x00, 0x00, // CRC
	}
	binary.LittleEndian.PutUint16(f[8:10], wire.CRC16(f[0:8]))
	return f
}

// buildDataFrame returns a frame with the given control byte carrying
// userData in CRC'd blocks, header CRC included.
func buildDataFrame(control uint8, userData []byte) []byte {
	f := buildFrame(control)
	f[2] = byte(5 + len(userData)) // #nosec G115 -- test data under 250 octets
	binary.LittleEndian.PutUint16(f[8:10], wire.CRC16(f[0:8]))
	return append(f, wire.AppendBlockCRCs(userData)...)
}

// directOperateTrip is the user data of a Direct Operate (FC 5) of one
// CROB, g12v1 index 7, TRIP + PULSE_ON (0x81): the breaker trip the
// write-ban exists to stop.
var directOperateTrip = []byte{
	0xC0, 0xC0, 0x05,
	0x0C, 0x01, 0x17, 0x01, 0x07,
	0x81, 0x01, 0x64, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00,
}

func readFullDNP3(r io.Reader) ([]byte, error) {
	buf := make([]byte, wire.HeaderLen)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func TestProxy_UserDataRefused(t *testing.T) {
	t.Parallel()
	client, clientSide := net.Pipe()
	upstream, upstreamSide := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = upstream.Close() }()
	defer func() { _ = clientSide.Close() }()
	defer func() { _ = upstreamSide.Close() }()

	h := dnp3.Default().ProxyHandler()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() { _ = h.Handle(ctx, clientSide, upstreamSide) }()

	upstreamGot := make(chan []byte, 1)
	go func() {
		buf, err := readFullDNP3(upstream)
		if err != nil {
			return
		}
		upstreamGot <- buf
	}()

	// Unconfirmed User Data: PRM=1 DIR=1 FC=4 -> 0xC4, carrying a Direct
	// Operate (a user-data frame without data is invalid and discarded).
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	req := buildDataFrame(0xC4, directOperateTrip)
	if _, err := client.Write(req); err != nil {
		t.Fatalf("client write: %v", err)
	}

	resp, err := readFullDNP3(client)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	// Refusal has control=0x0F (FC 15 Not Supported, PRM=0).
	if resp[3] != 0x0F {
		t.Fatalf("refusal control=0x%02x, want 0x0F", resp[3])
	}

	select {
	case got := <-upstreamGot:
		t.Fatalf("upstream received %d bytes on refusal: % x", len(got), got)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestProxy_RequestLinkStatusForwarded(t *testing.T) {
	t.Parallel()
	client, clientSide := net.Pipe()
	upstream, upstreamSide := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = upstream.Close() }()
	defer func() { _ = clientSide.Close() }()
	defer func() { _ = upstreamSide.Close() }()

	h := dnp3.Default().ProxyHandler()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() { _ = h.Handle(ctx, clientSide, upstreamSide) }()

	upstreamBuf := make(chan []byte, 1)
	go func() {
		buf, err := readFullDNP3(upstream)
		if err != nil {
			return
		}
		upstreamBuf <- buf
	}()

	// Request Link Status: PRM=1 DIR=1 FC=9 -> 0xC9.
	req := buildFrame(0xC9)
	if _, err := client.Write(req); err != nil {
		t.Fatalf("client write: %v", err)
	}

	select {
	case got := <-upstreamBuf:
		if !bytes.Equal(got, req) {
			t.Fatalf("forwarded bytes differ: want % x, got % x", req, got)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("upstream did not receive forwarded frame")
	}
}

// startProxy runs the default DNP3 proxy between two pipes and returns
// the master's end and the outstation's end.
func startProxy(t *testing.T) (client, upstream net.Conn) {
	t.Helper()
	client, clientSide := net.Pipe()
	upstream, upstreamSide := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = upstream.Close()
		_ = clientSide.Close()
		_ = upstreamSide.Close()
	})
	// net.Pipe is synchronous: a proxy that stops reading mid-frame
	// blocks the master's write, so a deadline turns that into a failure
	// instead of a hung test.
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	_ = upstream.SetDeadline(time.Now().Add(2 * time.Second))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)
	go func() { _ = dnp3.Default().ProxyHandler().Handle(ctx, clientSide, upstreamSide) }()
	return client, upstream
}

// upstreamFrames collects every 10-octet header-only frame the
// outstation side receives.
func upstreamFrames(upstream net.Conn) <-chan []byte {
	got := make(chan []byte, 4)
	go func() {
		for {
			buf, err := readFullDNP3(upstream)
			if err != nil {
				return
			}
			got <- buf
		}
	}()
	return got
}

// TestProxy_LinkFunctionNumbering: link function 1 is Reset of User
// Process (a reset) and 2 is Test Link States (Wireshark packet-dnp.c,
// nmap dnp3-info.nse). The table had them the other way round, so the
// read-only proxy forwarded a reset and refused a Test Link (PITF-074).
// Since PITF-081 a Reset of User Process, removed in IEEE 1815-2012,
// is an invalid frame and is discarded without a reply.
func TestProxy_LinkFunctionNumbering(t *testing.T) {
	t.Parallel()
	client, upstream := startProxy(t)
	got := upstreamFrames(upstream)

	// Reset of User Process: DIR=1 PRM=1 FC=1 -> 0xC1. Discarded. On a
	// synchronous pipe a reply nobody reads would block the proxy, and
	// the next write would hit the deadline.
	if _, err := client.Write(buildFrame(0xC1)); err != nil {
		t.Fatalf("client write: %v", err)
	}
	// Test Link States: DIR=1 PRM=1 FCV=1 FC=2 -> 0xD2. Forwarded.
	tl := buildFrame(0xD2)
	if _, err := client.Write(tl); err != nil {
		t.Fatalf("client write: %v", err)
	}
	select {
	case f := <-got:
		if !bytes.Equal(f, tl) {
			t.Fatalf("upstream got % x, want the Test Link frame % x (the reset must never arrive)", f, tl)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Test Link States was not forwarded")
	}
}

// TestProxy_RefusedUserDataKeepsStreamInSync: a refused user-data frame
// must be consumed whole, block CRCs included, or the next frame is
// read from the middle of the previous one. The first frame is the
// master's Read Class 0 from the CISA icsnpp-dnp3 capture (6 octets of
// user data plus its block CRC 34 4d).
func TestProxy_RefusedUserDataKeepsStreamInSync(t *testing.T) {
	t.Parallel()
	client, upstream := startProxy(t)
	got := upstreamFrames(upstream)

	read, err := hex.DecodeString("05640bc4050064006f36d0c3013c0106344d")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write(read); err != nil {
		t.Fatalf("client write: %v", err)
	}
	resp, err := readFullDNP3(client)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if resp[3] != 0x0F {
		t.Fatalf("user data: reply control=0x%02x, want 0x0F refusal", resp[3])
	}
	rls := wire.BuildRequestLinkStatus(5, 100)
	if _, err := client.Write(rls); err != nil {
		t.Fatalf("client write: %v", err)
	}
	select {
	case f := <-got:
		if !bytes.Equal(f, rls) {
			t.Fatalf("upstream got % x, want the Request Link Status % x", f, rls)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("the frame after a refused user-data frame was lost (stream out of sync)")
	}
}

// TestProxy_SecondaryFrameCarryingDataDiscarded: a Direct Operate TRIP
// wrapped in a frame with PRM cleared (control 0x84, "secondary FC 4",
// a function that does not exist) reached the outstation through the
// write-ban until 2026-10-14, because every PRM=0 frame classified as a
// read and was forwarded with its body (PITF-081). The same held for
// Request Link Status and Test Link carrying data. AN2013-004b Table 1
// says to discard all of them; the next valid frame still forwards.
func TestProxy_SecondaryFrameCarryingDataDiscarded(t *testing.T) {
	t.Parallel()
	for _, ctrl := range []uint8{0x84, 0x04, 0x8B, 0xC9, 0xD2} {
		client, upstream := startProxy(t)
		got := upstreamFrames(upstream)
		if _, err := client.Write(buildDataFrame(ctrl, directOperateTrip)); err != nil {
			t.Fatalf("ctrl 0x%02x: client write: %v", ctrl, err)
		}
		select {
		case f := <-got:
			t.Fatalf("ctrl 0x%02x: the frame carrying a Direct Operate reached the outstation: % x", ctrl, f)
		case <-time.After(100 * time.Millisecond):
		}
		rls := wire.BuildRequestLinkStatus(1, 0)
		if _, err := client.Write(rls); err != nil {
			t.Fatalf("ctrl 0x%02x: client write after the discarded frame: %v", ctrl, err)
		}
		select {
		case f := <-got:
			if !bytes.Equal(f, rls) {
				t.Fatalf("ctrl 0x%02x: upstream got % x, want only the Request Link Status (the Direct Operate must never arrive)", ctrl, f)
			}
		case <-time.After(500 * time.Millisecond):
			t.Fatalf("ctrl 0x%02x: the frame after a discarded one was lost (stream out of sync)", ctrl)
		}
	}
}

// TestProxy_ResyncAfterBadHeader: a header whose CRC is wrong cannot be
// trusted to frame anything, so the proxy forwards nothing of it and
// hunts for the next valid header, as AN2013-004b prescribes; line noise
// from a serial master behind a terminal server does not end the session.
func TestProxy_ResyncAfterBadHeader(t *testing.T) {
	t.Parallel()
	client, upstream := startProxy(t)
	got := upstreamFrames(upstream)
	bad := wire.BuildRequestLinkStatus(1, 0)
	bad[8] ^= 0x01
	rls := wire.BuildRequestLinkStatus(2, 0)
	in := append(append([]byte{0xFF, 0x05}, bad...), rls...)
	if _, err := client.Write(in); err != nil {
		t.Fatalf("client write: %v", err)
	}
	select {
	case f := <-got:
		if !bytes.Equal(f, rls) {
			t.Fatalf("upstream got % x, want only the valid Request Link Status % x", f, rls)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("the valid frame after a bad header was lost")
	}
}

// TestProxy_LinkAckForwarded: the header-only link replies a master
// returns to an outstation (ACK, with and without DFC, and LINK_STATUS)
// still cross the proxy after validation.
func TestProxy_LinkAckForwarded(t *testing.T) {
	t.Parallel()
	for _, ctrl := range []uint8{0x80, 0x90, 0x8B} {
		client, upstream := startProxy(t)
		got := upstreamFrames(upstream)
		f := buildFrame(ctrl)
		if _, err := client.Write(f); err != nil {
			t.Fatalf("ctrl 0x%02x: client write: %v", ctrl, err)
		}
		select {
		case u := <-got:
			if !bytes.Equal(u, f) {
				t.Fatalf("ctrl 0x%02x: upstream got % x, want % x", ctrl, u, f)
			}
		case <-time.After(500 * time.Millisecond):
			t.Fatalf("ctrl 0x%02x: a master's link reply was not forwarded", ctrl)
		}
	}
}
