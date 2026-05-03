package hartip_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"local/elsereno/internal/protocols/hartip"
	"local/elsereno/internal/protocols/hartip/wire"
)

func buildPacket(msgType, msgID uint8, seq uint16, body []byte) []byte {
	total := uint16(wire.HeaderLen + len(body)) // #nosec G115 -- bounded by test fixtures
	out := make([]byte, 0, int(total))
	out = append(out, wire.Version, msgType, msgID, 0x00)
	out = append(out, byte(seq>>8), byte(seq&0xFF))
	out = append(out, byte(total>>8), byte(total&0xFF))
	out = append(out, body...)
	return out
}

func readFullHartIP(r io.Reader) ([]byte, error) {
	buf := make([]byte, wire.HeaderLen)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	total := int(binary.BigEndian.Uint16(buf[6:8]))
	if total > wire.HeaderLen {
		body := make([]byte, total-wire.HeaderLen)
		if _, err := io.ReadFull(r, body); err != nil {
			return nil, err
		}
		return append(buf, body...), nil
	}
	return buf, nil
}

func TestProxy_TokenPassRefused(t *testing.T) {
	t.Parallel()
	client, clientSide := net.Pipe()
	upstream, upstreamSide := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = upstream.Close() }()
	defer func() { _ = clientSide.Close() }()
	defer func() { _ = upstreamSide.Close() }()

	h := hartip.Default().ProxyHandler()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() { _ = h.Handle(ctx, clientSide, upstreamSide) }()

	upstreamGot := make(chan []byte, 1)
	go func() {
		buf, err := readFullHartIP(upstream)
		if err != nil {
			return
		}
		upstreamGot <- buf
	}()

	req := buildPacket(wire.MsgRequest, wire.IDTokenPassPDU, 0x1234, []byte{0x00, 0x01, 0x02})
	if _, err := client.Write(req); err != nil {
		t.Fatalf("client write: %v", err)
	}

	resp, err := readFullHartIP(client)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if resp[2] != wire.IDSessionClose {
		t.Fatalf("refusal MsgID=0x%02x, want SessionClose", resp[2])
	}
	if resp[3] != 0x04 {
		t.Fatalf("refusal status=0x%02x, want 0x04", resp[3])
	}
	if resp[4] != 0x12 || resp[5] != 0x34 {
		t.Fatalf("sequence echo wrong: % x", resp[4:6])
	}

	select {
	case got := <-upstreamGot:
		t.Fatalf("upstream received %d bytes on refusal: % x", len(got), got)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestProxy_SessionInitiateForwarded(t *testing.T) {
	t.Parallel()
	client, clientSide := net.Pipe()
	upstream, upstreamSide := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = upstream.Close() }()
	defer func() { _ = clientSide.Close() }()
	defer func() { _ = upstreamSide.Close() }()

	h := hartip.Default().ProxyHandler()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() { _ = h.Handle(ctx, clientSide, upstreamSide) }()

	upstreamBuf := make(chan []byte, 1)
	go func() {
		buf, err := readFullHartIP(upstream)
		if err != nil {
			return
		}
		upstreamBuf <- buf
	}()

	req := buildPacket(wire.MsgRequest, wire.IDSessionInitiate, 0x0001, []byte{0x01, 0x00, 0x00, 0x00, 0x00})
	if _, err := client.Write(req); err != nil {
		t.Fatalf("client write: %v", err)
	}

	select {
	case got := <-upstreamBuf:
		if !bytes.Equal(got, req) {
			t.Fatalf("forwarded bytes differ: want % x, got % x", req, got)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("upstream did not receive session-initiate")
	}
}
