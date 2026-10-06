package dnp3_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"net"
	"testing"
	"time"

	"local/elsereno/internal/protocols/dnp3"
	"local/elsereno/internal/protocols/dnp3/wire"
)

// buildFrame returns a minimal link-layer-only DNP3 frame with the
// given control byte.
func buildFrame(control uint8) []byte {
	return []byte{
		wire.StartBytes[0], wire.StartBytes[1],
		0x05,       // length
		control,    // control
		0x00, 0x00, // dest
		0x01, 0x00, // src
		0x00, 0x00, // CRC (unused by proxy)
	}
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

	// Unconfirmed User Data: PRM=1 DIR=1 FC=4 -> 0xC4.
	req := buildFrame(0xC4)
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
func TestProxy_LinkFunctionNumbering(t *testing.T) {
	t.Parallel()
	client, upstream := startProxy(t)
	got := upstreamFrames(upstream)

	// Reset of User Process: DIR=1 PRM=1 FC=1 -> 0xC1. Refused.
	if _, err := client.Write(buildFrame(0xC1)); err != nil {
		t.Fatalf("client write: %v", err)
	}
	resp, err := readFullDNP3(client)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if resp[3] != 0x0F {
		t.Fatalf("Reset of User Process: reply control=0x%02x, want 0x0F refusal", resp[3])
	}
	// Test Link States: DIR=1 PRM=1 FC=2 -> 0xC2. Forwarded.
	tl := buildFrame(0xC2)
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
