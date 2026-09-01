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
)

// codesys-sim is a throwaway CODESYS v3 stand-in for the write-gate
// demo (scripts/demo-codesys-proxy.sh). It is NOT a real CODESYS
// runtime: it accepts TCP, reads whatever the gated proxy forwards,
// logs it, and answers with a small canned L7 response so the demo can
// show bytes flowing back through the gate. A refused command never
// reaches here (the proxy closes the connection), which is the whole
// point of the demo.
func main() {
	os.Exit(run())
}

func run() int {
	addr := flag.String("addr", "127.0.0.1:11740", "listen address (TCP)")
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", *addr)
	if err != nil {
		log.Println("codesys-sim: listen:", err)
		return 1
	}
	log.Printf("codesys-sim: listening on %s (tcp)", *addr)

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

// cannedResponse is a plausible L7 service response header: magic
// 0x55cd, header_size 0, service_id 0x82 (response to CmpApp),
// cmd_id 0. The proxy relays upstream->client verbatim, so this is
// enough to show the gate let the request through.
var cannedResponse = []byte{0x55, 0xcd, 0x00, 0x00, 0x82, 0x00, 0x00, 0x00}

// serve reads whatever the proxy forwards and answers each chunk with
// the canned response. CODESYS has no simple per-request framing the
// demo needs to honour: proving the bytes arrived is enough.
func serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	buf := make([]byte, 4096)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, err := conn.Read(buf)
		if n > 0 {
			log.Printf("codesys-sim: received %d bytes: % x", n, buf[:min(n, 16)])
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
