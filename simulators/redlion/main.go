package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"local/elsereno/internal/protocols/redlion/wire"
)

// redlion-sim is a throwaway Red Lion Crimson v3 stand-in for the
// write-gate demo (scripts/demo-redlion-proxy.sh). It is NOT a real
// Crimson panel: it accepts TCP, reads CR3 frames the gated proxy
// forwards, logs each one, and answers with a small canned CR3
// response. A refused frame never reaches here (the proxy closes the
// connection), which is what the demo shows.
func main() {
	os.Exit(run())
}

func run() int {
	addr := flag.String("addr", "127.0.0.1:7890", "listen address (TCP)")
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", *addr)
	if err != nil {
		log.Println("redlion-sim: listen:", err)
		return 1
	}
	log.Printf("redlion-sim: listening on %s (tcp)", *addr)

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
		go serve(conn)
	}
}

// cannedResponse is a well-formed CR3 frame: length 4, reg 0x0000,
// type 0x0200 (a "no data" response opcode). length is big-endian and
// counts the body (reg+type = 4 bytes).
var cannedResponse = []byte{0x00, 0x04, 0x00, 0x00, 0x02, 0x00}

// serve answers every CR3 frame the proxy forwards with the canned
// response until the client disconnects or an idle deadline hits.
func serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	for {
		_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		frame, err := wire.ReadFrame(conn)
		if len(frame) > 0 {
			t, _ := wire.ExtractType(frame)
			log.Printf("redlion-sim: received CR3 frame type=0x%04x (%d bytes)", uint16(t), len(frame))
			if _, werr := conn.Write(cannedResponse); werr != nil {
				return
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				log.Printf("read: %v", err)
			}
			return
		}
	}
}
