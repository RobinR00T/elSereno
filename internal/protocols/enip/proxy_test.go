package enip_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"local/elsereno/internal/protocols/enip"
	"local/elsereno/internal/protocols/enip/wire"
)

// buildEIP returns a full EIP encapsulation packet with an empty body.
func buildEIP(cmd uint16, session uint32) []byte {
	h := wire.Header{Command: cmd, SessionHandle: session}
	buf := wire.MarshalHeader(h)
	return buf[:]
}

// readFullEIP reads one complete EIP packet (header + body) from r.
// net.Pipe splits Write chunks, so io.ReadFull is required.
func readFullEIP(r io.Reader) ([]byte, error) {
	hdr := make([]byte, wire.HeaderLen)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	bodyLen := binary.LittleEndian.Uint16(hdr[2:4])
	if bodyLen == 0 {
		return hdr, nil
	}
	body := make([]byte, int(bodyLen))
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return append(hdr, body...), nil
}

func TestProxy_SendRRDataRefused(t *testing.T) {
	t.Parallel()
	client, clientSide := net.Pipe()
	upstream, upstreamSide := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = upstream.Close() }()
	defer func() { _ = clientSide.Close() }()
	defer func() { _ = upstreamSide.Close() }()

	h := enip.Default().ProxyHandler()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() { _ = h.Handle(ctx, clientSide, upstreamSide) }()

	upstreamGot := make(chan []byte, 1)
	go func() {
		buf, err := readFullEIP(upstream)
		if err != nil {
			return
		}
		upstreamGot <- buf
	}()

	req := buildEIP(wire.CmdSendRRData, 0xCAFEBABE)
	if _, err := client.Write(req); err != nil {
		t.Fatalf("client write: %v", err)
	}

	resp, err := readFullEIP(client)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if len(resp) != wire.HeaderLen {
		t.Fatalf("refusal len=%d, want %d", len(resp), wire.HeaderLen)
	}
	if status := binary.LittleEndian.Uint32(resp[8:12]); status != 1 {
		t.Fatalf("status=0x%x, want 0x1", status)
	}
	if binary.LittleEndian.Uint32(resp[4:8]) != 0xCAFEBABE {
		t.Fatalf("session echo missing")
	}

	select {
	case got := <-upstreamGot:
		t.Fatalf("upstream received %d bytes on refusal: % x", len(got), got)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestProxy_ListIdentityForwarded(t *testing.T) {
	t.Parallel()
	client, clientSide := net.Pipe()
	upstream, upstreamSide := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = upstream.Close() }()
	defer func() { _ = clientSide.Close() }()
	defer func() { _ = upstreamSide.Close() }()

	h := enip.Default().ProxyHandler()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() { _ = h.Handle(ctx, clientSide, upstreamSide) }()

	upstreamBuf := make(chan []byte, 1)
	go func() {
		buf, err := readFullEIP(upstream)
		if err != nil {
			return
		}
		upstreamBuf <- buf
	}()

	req := buildEIP(wire.CmdListIdentity, 0)
	if _, err := client.Write(req); err != nil {
		t.Fatalf("client write: %v", err)
	}

	select {
	case got := <-upstreamBuf:
		if !bytes.Equal(got, req) {
			t.Fatalf("forwarded bytes differ: want % x, got % x", req, got)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("upstream did not receive forwarded ListIdentity")
	}
}
