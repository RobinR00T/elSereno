package modbus_test

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"local/elsereno/internal/core"
	"local/elsereno/internal/protocols/modbus"
	"local/elsereno/internal/protocols/modbus/wire"
)

// plcSim accepts one connection, reads a frame, and applies `respond`
// to it. Used to stand in for a Modbus device in unit tests.
func plcSim(t *testing.T, respond func(in wire.Frame) wire.Frame) *net.TCPAddr {
	t.Helper()
	lc := &net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("addr type %T", ln.Addr())
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				for {
					f, err := wire.ReadFrame(c)
					if err != nil {
						return
					}
					resp := respond(f)
					if resp.PDU == nil {
						return
					}
					if err := wire.WriteFrame(c, resp); err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	return addr
}

func TestProbeAcceptedAndDeviceID(t *testing.T) {
	t.Parallel()
	addr := plcSim(t, func(in wire.Frame) wire.Frame {
		//nolint:exhaustive // test only covers the FCs the probe sends
		switch in.FunctionCode() {
		case wire.FCReadCoils:
			// Respond with 1 byte of coil state.
			return wire.Frame{
				MBAP: wire.MBAP{TxID: in.MBAP.TxID, Unit: in.MBAP.Unit},
				PDU:  []byte{byte(wire.FCReadCoils), 0x01, 0x00},
			}
		case wire.FCEncapsulatedInterface:
			// Minimal FC43/14 response with VendorName and ProductCode.
			pdu := []byte{
				0x2B, 0x0E, 0x01, 0x00, 0x00, 0x02,
				0x00, 0x04, 'A', 'C', 'M', 'E',
				0x01, 0x05, 'P', 'L', 'C', '-', '1',
			}
			return wire.Frame{
				MBAP: wire.MBAP{TxID: in.MBAP.TxID, Unit: in.MBAP.Unit},
				PDU:  pdu,
			}
		}
		return wire.Frame{}
	})
	p := modbus.Default()
	p.DialTimeout = 2 * time.Second
	p.IOTimeout = 500 * time.Millisecond
	port, _ := core.NewPort(addr.Port)
	tg := core.Target{Address: addr.AddrPort().Addr().Unmap(), Port: port}
	f, err := p.Probe(context.Background(), tg)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if f.Protocol != modbus.Name {
		t.Fatalf("Protocol=%q", f.Protocol)
	}
	if f.Score < 0 || f.Score > 100 {
		t.Fatalf("Score out of range: %d", f.Score)
	}
}

func TestProbeExceptionFromDevice(t *testing.T) {
	t.Parallel()
	addr := plcSim(t, func(in wire.Frame) wire.Frame {
		return wire.Frame{
			MBAP: wire.MBAP{TxID: in.MBAP.TxID, Unit: in.MBAP.Unit},
			PDU:  []byte{byte(wire.FCReadCoils) | 0x80, byte(wire.ExIllegalDataAddress)},
		}
	})
	p := modbus.Default()
	p.DialTimeout = 2 * time.Second
	p.IOTimeout = 500 * time.Millisecond
	port, _ := core.NewPort(addr.Port)
	tg := core.Target{Address: addr.AddrPort().Addr().Unmap(), Port: port}
	_, err := p.Probe(context.Background(), tg)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
}

// proxyPipe uses net.Pipe() to drive the modbus proxyHandler. It
// returns what the proxy forwarded upstream and what it replied to
// the client. It waits for the cancellation to make sure the two
// forwarding goroutines flushed their output.
func proxyPipe(t *testing.T, clientSent []byte) (forwardedToUpstream, replyToClient []byte) {
	t.Helper()

	// Build the two ends.
	clientSide, proxyClient := net.Pipe()
	proxyUpstream, upstreamSide := net.Pipe()

	// Deadlines so the test never hangs.
	deadline := time.Now().Add(1 * time.Second)
	_ = clientSide.SetDeadline(deadline)
	_ = proxyClient.SetDeadline(deadline)
	_ = proxyUpstream.SetDeadline(deadline)
	_ = upstreamSide.SetDeadline(deadline)

	// Run the proxy.
	ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
	defer cancel()
	h := modbus.Default().ProxyHandler()
	proxyDone := make(chan struct{})
	go func() {
		defer close(proxyDone)
		_ = h.Handle(ctx, proxyClient, proxyUpstream)
	}()

	// Drain what the proxy sends upstream in the background.
	upstreamCh := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 4096)
		var acc []byte
		for {
			n, err := upstreamSide.Read(buf)
			if n > 0 {
				acc = append(acc, buf[:n]...)
			}
			if err != nil {
				break
			}
		}
		upstreamCh <- acc
	}()

	// Drain what the proxy sends back to the client.
	clientCh := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 4096)
		var acc []byte
		for {
			n, err := clientSide.Read(buf)
			if n > 0 {
				acc = append(acc, buf[:n]...)
			}
			if err != nil {
				break
			}
		}
		clientCh <- acc
	}()

	// Feed the request from the "client" side.
	if _, err := clientSide.Write(clientSent); err != nil {
		t.Fatalf("write client: %v", err)
	}

	// Give the proxy a moment to process, then tear everything down
	// so the drain goroutines return.
	time.Sleep(100 * time.Millisecond)
	_ = clientSide.Close()
	_ = upstreamSide.Close()
	_ = proxyClient.Close()
	_ = proxyUpstream.Close()
	cancel()
	<-proxyDone

	return <-upstreamCh, <-clientCh
}

// TestProxyBlocksWrites drives every CategoryWrite function code
// through the proxy and confirms that it never reaches upstream and
// that the client receives an IllegalFunction exception.
func TestProxyBlocksWrites(t *testing.T) {
	t.Parallel()
	writes := []wire.FunctionCode{
		wire.FCWriteSingleCoil,
		wire.FCWriteSingleRegister,
		wire.FCWriteMultipleCoils,
		wire.FCWriteMultipleRegisters,
		wire.FCWriteFileRecord,
		wire.FCMaskWriteRegister,
		wire.FCReadWriteMultipleRegisters,
	}
	for _, fc := range writes {
		fc := fc
		t.Run(fmt.Sprintf("FC_0x%02x", uint8(fc)), func(t *testing.T) {
			t.Parallel()
			req := wire.Frame{
				MBAP: wire.MBAP{TxID: 1, Unit: 1},
				PDU:  []byte{byte(fc), 0x00, 0x00, 0x00, 0x01},
			}
			var enc bytes.Buffer
			if err := wire.WriteFrame(&enc, req); err != nil {
				t.Fatalf("WriteFrame: %v", err)
			}
			upstream, replied := proxyPipe(t, enc.Bytes())
			if len(upstream) != 0 {
				t.Fatalf("write FC 0x%02x leaked %d bytes upstream", uint8(fc), len(upstream))
			}
			// Parse the client-bound reply and assert it's an
			// IllegalFunction exception on the same FC.
			resp, err := wire.ReadFrame(bytes.NewReader(replied))
			if err != nil {
				t.Fatalf("parse reply: %v (replied=%q)", err, replied)
			}
			if !resp.IsExceptionFrame() {
				t.Fatalf("proxy did not emit an exception frame")
			}
			code, _ := resp.ExceptionCode()
			if code != wire.ExIllegalFunction {
				t.Fatalf("exception code=%d, want IllegalFunction", code)
			}
		})
	}
}

func TestProxyAllowsReads(t *testing.T) {
	t.Parallel()
	req := wire.BuildReadCoilsRequest(0x1234, 0x11)
	var enc bytes.Buffer
	_ = wire.WriteFrame(&enc, req)
	upstream, _ := proxyPipe(t, enc.Bytes())
	if len(upstream) == 0 {
		t.Fatal("proxy did not forward a Read Coils request")
	}
	parsed, err := wire.ReadFrame(bytes.NewReader(upstream))
	if err != nil {
		t.Fatalf("parse forwarded: %v", err)
	}
	if parsed.FunctionCode() != wire.FCReadCoils {
		t.Fatalf("forwarded FC=%d", parsed.FunctionCode())
	}
}

func TestMetadata(t *testing.T) {
	t.Parallel()
	md := modbus.Default().Metadata()
	if md.Name != modbus.Name {
		t.Fatalf("Name=%q", md.Name)
	}
}
