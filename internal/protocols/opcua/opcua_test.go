package opcua_test

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"local/elsereno/internal/core"
	"local/elsereno/internal/protocols/opcua"
	"local/elsereno/internal/protocols/opcua/wire"
)

// fakeServer accepts one connection, reads a HEL frame, and
// replies with the handler-supplied bytes. Returns the bound
// port so the test can hand it to the plugin probe.
func fakeServer(t *testing.T, handler func(hel []byte) (reply []byte)) int {
	t.Helper()
	lc := net.ListenConfig{}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ln, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		// Read the 8-byte header first.
		hdr := make([]byte, wire.HeaderSize)
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return
		}
		total := binary.LittleEndian.Uint32(hdr[4:8])
		body := make([]byte, int(total)-wire.HeaderSize)
		_, _ = io.ReadFull(conn, body)
		reply := handler(append(hdr, body...))
		if len(reply) > 0 {
			_, _ = conn.Write(reply)
		}
	}()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	return port
}

func probeAt(port int) *core.Finding {
	plug := opcua.Default()
	plug.DialTimeout = 1 * time.Second
	plug.IOTimeout = 1 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	f, _ := plug.Probe(ctx, core.Target{
		Address: netip.MustParseAddr("127.0.0.1"),
		Port:    core.Port(port), //nolint:gosec // G115 — port fits in uint16 by construction
	})
	return f
}

func TestProbe_AckPath(t *testing.T) {
	port := fakeServer(t, func(_ []byte) []byte {
		// Minimal ACK reply: header + 20 bytes body.
		body := make([]byte, 20)
		binary.LittleEndian.PutUint32(body[0:4], 0)
		binary.LittleEndian.PutUint32(body[4:8], 65536)
		binary.LittleEndian.PutUint32(body[8:12], 65536)
		binary.LittleEndian.PutUint32(body[12:16], 16777216)
		binary.LittleEndian.PutUint32(body[16:20], 5000)
		frame := make([]byte, wire.HeaderSize+len(body))
		copy(frame[0:3], "ACK")
		frame[3] = 'F'
		// #nosec G115 — frame length is a fixed 28 bytes by construction
		binary.LittleEndian.PutUint32(frame[4:8], uint32(wire.HeaderSize+len(body)))
		copy(frame[wire.HeaderSize:], body)
		return frame
	})

	f := probeAt(port)
	if f == nil {
		t.Fatal("expected finding")
	}
	if f.Protocol != opcua.Name {
		t.Fatalf("protocol = %q", f.Protocol)
	}
	if f.Factors["capability"] != 60 {
		t.Fatalf("ua-confirmed capability should be 60, got %d", f.Factors["capability"])
	}
}

func TestProbe_ErrPath(t *testing.T) {
	port := fakeServer(t, func(_ []byte) []byte {
		reason := "Bad_ResourceLimitsExceeded"
		body := make([]byte, 8+len(reason))
		binary.LittleEndian.PutUint32(body[0:4], 0x80A40000)
		// #nosec G115 — reason literal length fits uint32
		binary.LittleEndian.PutUint32(body[4:8], uint32(len(reason)))
		copy(body[8:], reason)
		frame := make([]byte, wire.HeaderSize+len(body))
		copy(frame[0:3], "ERR")
		frame[3] = 'F'
		// #nosec G115 — frame length fits uint32 by construction
		binary.LittleEndian.PutUint32(frame[4:8], uint32(wire.HeaderSize+len(body)))
		copy(frame[wire.HeaderSize:], body)
		return frame
	})

	f := probeAt(port)
	if f == nil {
		t.Fatal("expected finding")
	}
	if f.Factors["capability"] != 60 {
		t.Fatalf("ua-err still means UA server (capability=60), got %d", f.Factors["capability"])
	}
}

func TestProbe_NonUABytes(t *testing.T) {
	port := fakeServer(t, func(_ []byte) []byte {
		return []byte("HTTP/1.1 400 Bad Request\r\n\r\n")
	})

	f := probeAt(port)
	if f == nil {
		t.Fatal("expected finding")
	}
	// Non-UA server: capability stays at the default (30).
	if f.Factors["capability"] != 30 {
		t.Fatalf("non-UA capability should be 30, got %d", f.Factors["capability"])
	}
}

func TestMetadata_DefaultPortIs4840(t *testing.T) {
	meta := opcua.Default().Metadata()
	if meta.DefaultPort != 4840 {
		t.Fatalf("DefaultPort = %d, want 4840", meta.DefaultPort)
	}
	if meta.Name != "opcua" {
		t.Fatalf("Name = %q", meta.Name)
	}
	if !strings.Contains(meta.Description, "OPC UA") {
		t.Fatalf("Description missing protocol name: %q", meta.Description)
	}
}

func TestProxy_EmitsUAErrFrame(t *testing.T) {
	// The default proxy refuses client input. Drive it through an
	// io.Pipe so we can inspect what it writes to `client`.
	clientR, clientW := net.Pipe()
	t.Cleanup(func() { _ = clientR.Close(); _ = clientW.Close() })

	// Upstream is never read because the handler refuses; use a
	// discarding pipe.
	upstreamR, upstreamW := net.Pipe()
	t.Cleanup(func() { _ = upstreamR.Close(); _ = upstreamW.Close() })

	errCh := make(chan error, 1)
	go func() {
		errCh <- opcua.Default().ProxyHandler().Handle(context.Background(),
			struct {
				io.Reader
				io.Writer
			}{clientR, clientW},
			struct {
				io.Reader
				io.Writer
			}{upstreamR, upstreamW},
		)
	}()

	buf := make([]byte, 64)
	_ = clientR.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	n, _ := clientR.Read(buf)
	if n < wire.HeaderSize {
		t.Fatalf("proxy wrote %d bytes, want ≥ %d", n, wire.HeaderSize)
	}
	h, err := wire.ParseHeader(buf[:wire.HeaderSize])
	if err != nil {
		t.Fatalf("parse refusal header: %v", err)
	}
	if h.Type != wire.MessageError {
		t.Fatalf("proxy must refuse with ERR, got %q", h.Type)
	}

	select {
	case got := <-errCh:
		if got == nil {
			t.Fatal("handler must return an error when refusing")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("handler did not return")
	}
}
