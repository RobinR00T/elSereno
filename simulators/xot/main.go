// Command xot-sim is a minimal XOT (RFC 1613) responder for the
// integration suite. It accepts TCP connections on --listen, reads a
// single Call Request, and replies with a configurable response —
// either a Clear Indication with cause/diag, a Call Accepted, or
// silence.
//
// Usage:
//
//	xot-sim --listen 127.0.0.1:1998 --response clear --cause 0x05 --diag 0x00
//
// It runs until SIGINT/SIGTERM; findings hit the scanner end-to-end.
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"local/elsereno/internal/protocols/xot/wire"
)

func main() {
	os.Exit(runMain())
}

func runMain() int {
	listen := flag.String("listen", "127.0.0.1:1998", "bind address")
	resp := flag.String("response", "clear", "response kind: clear|accept|restart|silence")
	causeHex := flag.String("cause", "0x05", "clear cause byte (hex; clear response only)")
	diagHex := flag.String("diag", "0x00", "clear diag byte (hex; clear response only)")
	flag.Parse()

	cause, err := parseHexByte(*causeHex)
	if err != nil {
		log.Printf("bad --cause: %v", err)
		return 2
	}
	diag, err := parseHexByte(*diagHex)
	if err != nil {
		log.Printf("bad --diag: %v", err)
		return 2
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	lc := &net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", *listen)
	if err != nil {
		log.Printf("listen %s: %v", *listen, err)
		return 1
	}
	defer func() { _ = ln.Close() }()

	log.Printf("xot-sim listening on %s (response=%s)", *listen, *resp)

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
		go serve(ctx, conn, *resp, cause, diag)
	}
}

func serve(ctx context.Context, conn net.Conn, kind string, cause, diag byte) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	packet, err := wire.ReadXOTFrame(conn)
	if err != nil {
		if !errors.Is(err, io.EOF) && ctx.Err() == nil {
			log.Printf("read: %v", err)
		}
		return
	}
	log.Printf("incoming frame: %s LCN=%d PTI=0x%02x", packet.Type, packet.LCN, packet.PTI)

	var payload []byte
	switch kind {
	case "accept":
		payload = []byte{0x10, 0x01, uint8(wire.PacketCallAccepted), 0x00, 0x00}
	case "restart":
		payload = []byte{0x10, 0x00, uint8(wire.PacketRestartRequest), 0x00, 0x00}
	case "silence":
		return
	case "clear":
		fallthrough
	default:
		payload = []byte{0x10, 0x01, uint8(wire.PacketClearRequest), cause, diag}
	}
	if err := wire.WriteXOTFrame(conn, payload); err != nil {
		log.Printf("write: %v", err)
	}
}

// parseHexByte accepts "0xNN", "NN", or "N".
func parseHexByte(s string) (byte, error) {
	if len(s) > 2 && (s[:2] == "0x" || s[:2] == "0X") {
		s = s[2:]
	}
	if len(s) == 1 {
		s = "0" + s
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		// Allow decimal as a fallback so --cause 5 works.
		n, e2 := strconv.Atoi(s)
		if e2 != nil || n < 0 || n > 0xff {
			return 0, fmt.Errorf("%q is not a hex or decimal byte", s)
		}
		return byte(n), nil
	}
	if len(b) != 1 {
		return 0, fmt.Errorf("%q: want exactly one byte", s)
	}
	_ = os.Stderr
	return b[0], nil
}
