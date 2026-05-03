package s7_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"local/elsereno/internal/protocols/s7"
	"local/elsereno/internal/protocols/s7/wire"
)

// readFullTPKT reads one complete TPKT envelope from r into a buffer.
// net.Pipe delivers Write calls chunk-by-chunk; a single Read can
// return fewer bytes than the full envelope, so tests loop with
// io.ReadFull after peeking at the 2-byte length field.
func readFullTPKT(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	total := binary.BigEndian.Uint16(hdr[2:4])
	if total < 4 {
		return nil, errors.New("bad tpkt length")
	}
	rest := make([]byte, int(total)-4)
	if _, err := io.ReadFull(r, rest); err != nil {
		return nil, err
	}
	out := make([]byte, 0, int(total))
	out = append(out, hdr[:]...)
	out = append(out, rest...)
	return out, nil
}

// buildCOTPDataS7 builds a TPKT-wrapped COTP-DT + S7 PDU with the
// given ROSCTR and function byte. Used to drive the proxy with both
// "read" and "write" client frames.
func buildCOTPDataS7(rosctr, fc byte) []byte {
	// S7 header (10 bytes) + param (2 bytes).
	s7pdu := []byte{
		0x32, rosctr,
		0x00, 0x00,
		0x00, 0x07, // pduRef
		0x00, 0x02, // paramLen
		0x00, 0x00, // dataLen
		fc, 0x00,
	}
	cotp := []byte{0x02, 0xF0, 0x80}
	payload := make([]byte, 0, len(cotp)+len(s7pdu))
	payload = append(payload, cotp...)
	payload = append(payload, s7pdu...)
	// Prepend TPKT header; total is bounded by the fixtures above.
	total := uint16(4 + len(payload)) // #nosec G115 -- bounded by test fixtures
	out := make([]byte, 0, int(total))
	out = append(out, 0x03, 0x00, byte(total>>8), byte(total&0xFF))
	out = append(out, payload...)
	return out
}

func TestProxy_WriteFrameRefused(t *testing.T) {
	t.Parallel()
	client, clientSide := net.Pipe()
	upstream, upstreamSide := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = upstream.Close() }()
	defer func() { _ = clientSide.Close() }()
	defer func() { _ = upstreamSide.Close() }()

	h := s7.Default().ProxyHandler()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go func() {
		_ = h.Handle(ctx, clientSide, upstreamSide)
	}()

	upstreamGot := make(chan []byte, 1)
	go func() {
		buf, err := readFullTPKT(upstream)
		if err != nil {
			return
		}
		upstreamGot <- buf
	}()

	write := buildCOTPDataS7(wire.ROSCTRJob, byte(wire.FuncWriteVar))
	if _, err := client.Write(write); err != nil {
		t.Fatalf("client write: %v", err)
	}

	resp, err := readFullTPKT(client)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	// TPKT(4) + COTP-DT(3) + S7 AckData(12) = 19 bytes.
	if len(resp) != 19 {
		t.Fatalf("refusal len=%d, want 19 (% x)", len(resp), resp)
	}
	// err class at [17], err code at [18].
	if resp[17] != 0x85 || resp[18] != 0x01 {
		t.Fatalf("expected err 0x85/0x01, got % x (full % x)", resp[17:19], resp)
	}

	select {
	case got := <-upstreamGot:
		t.Fatalf("upstream received %d bytes on write-block: % x", len(got), got)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestProxy_ReadFrameForwarded(t *testing.T) {
	t.Parallel()
	client, clientSide := net.Pipe()
	upstream, upstreamSide := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = upstream.Close() }()
	defer func() { _ = clientSide.Close() }()
	defer func() { _ = upstreamSide.Close() }()

	h := s7.Default().ProxyHandler()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	go func() { _ = h.Handle(ctx, clientSide, upstreamSide) }()

	upstreamBuf := make(chan []byte, 1)
	go func() {
		buf, err := readFullTPKT(upstream)
		if err != nil {
			return
		}
		upstreamBuf <- buf
	}()

	read := buildCOTPDataS7(wire.ROSCTRJob, byte(wire.FuncReadVar))
	if _, err := client.Write(read); err != nil {
		t.Fatalf("client write: %v", err)
	}

	select {
	case got := <-upstreamBuf:
		if !bytes.Equal(got, read) {
			t.Fatalf("forwarded bytes differ:\nwant % x\ngot  % x", read, got)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("upstream did not receive forwarded read frame")
	}
}
