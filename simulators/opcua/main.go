// Command opcua-sim is a minimal OPC UA TCP responder for the
// integration suite. It accepts a client Hello (HEL) and replies
// with either an ACK (matching the client's endpoint URL against
// an allowlist) or an ERR frame. Nothing above the UA-TCP
// transport layer is implemented — SecureChannel / Session /
// service calls arrive with v1.2's offensive/write/opcua work.
//
// Operators who need a full OPC UA server (full endpoints,
// services, address space) should use the upstream `open62541`
// reference implementation. This Go responder exists so CI runs
// on an isolated network without pulling a C toolchain.
package main

import (
	"context"
	"encoding/binary"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"local/elsereno/internal/protocols/opcua/wire"
)

func main() {
	os.Exit(run())
}

// run is the testable body of main — keeps all defers intact
// before the final os.Exit sits on the outermost caller.
func run() int {
	addr := flag.String("addr", "127.0.0.1:4840", "listen address")
	mode := flag.String("mode", "ack", "reply mode: ack | err")
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", *addr)
	if err != nil {
		log.Println("opcua-sim: listen:", err)
		return 1
	}
	log.Printf("opcua-sim: listening on %s (mode=%s)", *addr, *mode)

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return 0
			}
			log.Printf("accept: %v", err)
			continue
		}
		go serve(ctx, conn, *mode)
	}
}

func serve(ctx context.Context, conn net.Conn, mode string) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	hdr := make([]byte, wire.HeaderSize)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return
	}
	h, err := wire.ParseHeader(hdr)
	if err != nil || h.Type != wire.MessageHello {
		reply := buildErr(0x80AB0000, "Bad_TcpMessageTypeInvalid") // Bad_TcpMessageTypeInvalid
		_, _ = conn.Write(reply)
		return
	}
	body := make([]byte, int(h.Length)-wire.HeaderSize)
	if _, err := io.ReadFull(conn, body); err != nil {
		return
	}

	switch mode {
	case "err":
		_, _ = conn.Write(buildErr(0x80A40000, "Bad_ResourceLimitsExceeded"))
	default:
		_, _ = conn.Write(buildAck())
	}
	_ = ctx
}

// buildAck emits a minimal ACK reply with open62541-default
// buffer sizes. Callers cannot continue past this point because
// the simulator does not implement SecureChannel.
func buildAck() []byte {
	body := make([]byte, 20)
	binary.LittleEndian.PutUint32(body[0:4], 0)
	binary.LittleEndian.PutUint32(body[4:8], 65536)
	binary.LittleEndian.PutUint32(body[8:12], 65536)
	binary.LittleEndian.PutUint32(body[12:16], 16777216)
	binary.LittleEndian.PutUint32(body[16:20], 5000)
	return wrap("ACK", body)
}

// buildErr emits an ERR frame with the given StatusCode + reason.
func buildErr(code uint32, reason string) []byte {
	body := make([]byte, 8+len(reason))
	binary.LittleEndian.PutUint32(body[0:4], code)
	// #nosec G115 — hard-coded short reasons fit uint32
	binary.LittleEndian.PutUint32(body[4:8], uint32(len(reason)))
	copy(body[8:], reason)
	return wrap("ERR", body)
}

// wrap inlines the UA-TCP 8-byte header prefix. Kept local to
// the simulator so it doesn't leak into the production plugin
// API surface.
func wrap(typeStr string, body []byte) []byte {
	out := make([]byte, wire.HeaderSize+len(body))
	copy(out[0:3], typeStr)
	out[3] = byte(wire.ChunkFinal)
	// #nosec G115 — total frame length fits uint32 by construction
	binary.LittleEndian.PutUint32(out[4:8], uint32(wire.HeaderSize+len(body)))
	copy(out[wire.HeaderSize:], body)
	return out
}
