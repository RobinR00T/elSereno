package dnp3_test

import (
	"bytes"
	"context"
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
