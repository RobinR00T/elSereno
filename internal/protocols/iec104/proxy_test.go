package iec104_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"local/elsereno/internal/protocols/iec104"
	"local/elsereno/internal/protocols/iec104/wire"
)

// buildApdu returns a 6-byte APCI plus an optional payload. Length
// is bounded by test fixtures well below 253 so the uint8 cast is
// safe.
func buildApdu(control [4]byte, payload []byte) []byte {
	apduLen := uint8(4 + len(payload)) //nolint:gosec // bounded by test fixtures
	out := make([]byte, 0, 2+int(apduLen))
	out = append(out, wire.Start, apduLen)
	out = append(out, control[:]...)
	out = append(out, payload...)
	return out
}

// readFullAPDU reads one complete APDU (APCI + payload).
func readFullAPDU(r io.Reader) ([]byte, error) {
	apci := make([]byte, wire.APCILen)
	if _, err := io.ReadFull(r, apci); err != nil {
		return nil, err
	}
	// payload size = Length - 4 (control bytes already read as part of APCI).
	payloadLen := int(apci[1]) - 4
	if payloadLen <= 0 {
		return apci, nil
	}
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return append(apci, payload...), nil
}

func TestProxy_IFrameRefused(t *testing.T) {
	t.Parallel()
	client, clientSide := net.Pipe()
	upstream, upstreamSide := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = upstream.Close() }()
	defer func() { _ = clientSide.Close() }()
	defer func() { _ = upstreamSide.Close() }()

	h := iec104.Default().ProxyHandler()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() { _ = h.Handle(ctx, clientSide, upstreamSide) }()

	upstreamGot := make(chan []byte, 1)
	go func() {
		buf, err := readFullAPDU(upstream)
		if err != nil {
			return
		}
		upstreamGot <- buf
	}()

	// I-frame: Control[0] bit 0 = 0 (I-format). Carry a bogus ASDU.
	iframe := buildApdu([4]byte{0x00, 0x00, 0x00, 0x00},
		[]byte{0x2E, 0x01, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x81})
	if _, err := client.Write(iframe); err != nil {
		t.Fatalf("client write: %v", err)
	}

	resp, err := readFullAPDU(client)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	// Refusal is a STOPDT_act U-frame: 68 04 13 00 00 00.
	if !bytes.Equal(resp, []byte{0x68, 0x04, 0x13, 0x00, 0x00, 0x00}) {
		t.Fatalf("refusal bytes = % x, want 68 04 13 00 00 00", resp)
	}

	select {
	case got := <-upstreamGot:
		t.Fatalf("upstream received %d bytes on refusal: % x", len(got), got)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestProxy_UFrameForwarded(t *testing.T) {
	t.Parallel()
	client, clientSide := net.Pipe()
	upstream, upstreamSide := net.Pipe()
	defer func() { _ = client.Close() }()
	defer func() { _ = upstream.Close() }()
	defer func() { _ = clientSide.Close() }()
	defer func() { _ = upstreamSide.Close() }()

	h := iec104.Default().ProxyHandler()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() { _ = h.Handle(ctx, clientSide, upstreamSide) }()

	upstreamBuf := make(chan []byte, 1)
	go func() {
		buf, err := readFullAPDU(upstream)
		if err != nil {
			return
		}
		upstreamBuf <- buf
	}()

	// U-frame: STARTDT act control 0x07.
	uframe := buildApdu([4]byte{0x07, 0x00, 0x00, 0x00}, nil)
	if _, err := client.Write(uframe); err != nil {
		t.Fatalf("client write: %v", err)
	}

	select {
	case got := <-upstreamBuf:
		if !bytes.Equal(got, uframe) {
			t.Fatalf("forwarded bytes differ: want % x, got % x", uframe, got)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("upstream did not receive U-frame")
	}
}
