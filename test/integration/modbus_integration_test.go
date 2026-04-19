//go:build integration

package integration_test

import (
	"bytes"
	"context"
	"net"
	"os"
	"testing"
	"time"

	"local/elsereno/internal/core"
	"local/elsereno/internal/protocols/modbus"
	"local/elsereno/internal/protocols/modbus/wire"
	"local/elsereno/internal/proxy"
)

// TestModbusProxyBlocksWriteEndToEnd stands up the proxy framework,
// an upstream listener that would accept any frame, and confirms
// that a client write is short-circuited with IllegalFunction before
// it ever reaches upstream.
func TestModbusProxyBlocksWriteEndToEnd(t *testing.T) {
	if os.Getenv("ELSERENO_SKIP_NET") != "" {
		t.Skip("ELSERENO_SKIP_NET set")
	}

	// Upstream accepts + records what it sees.
	lc := &net.ListenConfig{}
	upLn, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	defer func() { _ = upLn.Close() }()

	upstreamSeen := make(chan []byte, 1)
	go func() {
		conn, err := upLn.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		upstreamSeen <- buf[:n]
	}()

	// Start the proxy framework wiring the modbus Handler.
	p, err := proxy.New(proxy.Options{
		Listen:   "127.0.0.1:0",
		Upstream: upLn.Addr().String(),
		Handler:  modbus.Default().ProxyHandler(),
	})
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = p.Run(ctx) }()
	for i := 0; i < 100 && p.Addr() == nil; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if p.Addr() == nil {
		t.Fatal("proxy never bound")
	}

	// Client issues a FC 5 (Write Single Coil) write through the proxy.
	d := net.Dialer{Timeout: 1 * time.Second}
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer dialCancel()
	c, err := d.DialContext(dialCtx, "tcp", p.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(1 * time.Second))

	req := wire.Frame{
		MBAP: wire.MBAP{TxID: 1, Unit: 1},
		PDU:  []byte{byte(wire.FCWriteSingleCoil), 0x00, 0x00, 0xFF, 0x00},
	}
	var enc bytes.Buffer
	_ = wire.WriteFrame(&enc, req)
	if _, err := c.Write(enc.Bytes()); err != nil {
		t.Fatalf("client write: %v", err)
	}

	// The proxy must reply with an exception.
	resp, err := wire.ReadFrame(c)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if !resp.IsExceptionFrame() {
		t.Fatalf("expected exception response, got FC=0x%02x", resp.PDU[0])
	}
	code, _ := resp.ExceptionCode()
	if code != wire.ExIllegalFunction {
		t.Fatalf("exception=%d, want IllegalFunction", code)
	}

	// Upstream must have never received anything.
	select {
	case b := <-upstreamSeen:
		t.Fatalf("upstream received %d bytes; expected none", len(b))
	case <-time.After(150 * time.Millisecond):
	}

	_ = core.SeverityFromScore
}
