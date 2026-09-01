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

	"local/elsereno/internal/protocols/gesrtp/wire"
)

// gesrtp-sim is a throwaway GE-SRTP stand-in for the write-gate demo
// (scripts/demo-gesrtp-proxy.sh). It is NOT a real PACSystems PLC: it
// accepts TCP, reads the 56-byte SRTP mailboxes the gated proxy
// forwards, logs each service code, and answers with a canned response
// mailbox. A refused mailbox never reaches here (the proxy closes the
// connection), which is what the demo shows.
func main() {
	os.Exit(run())
}

func run() int {
	addr := flag.String("addr", "127.0.0.1:18245", "listen address (TCP)")
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", *addr)
	if err != nil {
		log.Println("gesrtp-sim: listen:", err)
		return 1
	}
	log.Printf("gesrtp-sim: listening on %s (tcp)", *addr)

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

// cannedResponse is a 56-byte SRTP response mailbox (pkt type 0x03).
func cannedResponse() []byte {
	m := make([]byte, wire.MailboxLen)
	m[0] = 0x03 // response
	return m
}

// serve answers every SRTP mailbox the proxy forwards with the canned
// response until the client disconnects or an idle deadline hits.
func serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	for {
		_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		mb, err := wire.ReadMailbox(conn)
		if len(mb) > 0 {
			svc, _ := wire.ExtractServiceCode(mb)
			log.Printf("gesrtp-sim: received mailbox service=0x%02x (%d bytes)", byte(svc), len(mb))
			if _, werr := conn.Write(cannedResponse()); werr != nil {
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
