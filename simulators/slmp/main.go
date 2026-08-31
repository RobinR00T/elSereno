package main

import (
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"local/elsereno/internal/protocols/slmp/wire"
)

func main() {
	os.Exit(run())
}

// run is the testable body of main so the deferred cancel stays
// intact before os.Exit on the outermost caller.
func run() int {
	addr := flag.String("addr", "127.0.0.1:5007", "listen address (TCP)")
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", *addr)
	if err != nil {
		log.Println("slmp-sim: listen:", err)
		return 1
	}
	log.Printf("slmp-sim: listening on %s (tcp)", *addr)

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

// serve answers every 3E-binary frame on conn with a success
// response until the client disconnects or an idle deadline hits.
func serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	for {
		_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		frame, err := wire.ReadFrame(conn)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				log.Printf("read: %v", err)
			}
			return
		}
		if _, err := conn.Write(respond(frame)); err != nil {
			return
		}
	}
}

// respond builds a success SLMP response for a request frame. The
// routing bytes are echoed, the end code is 0x0000, and command-
// specific payloads make the fingerprint path work: READ CPU MODEL
// NAME returns a model + type code, DEVICE READ a couple of words.
func respond(req []byte) []byte {
	cmd, _ := wire.ExtractCommand(req)
	var payload []byte
	switch cmd {
	case wire.CmdReadCPUModelName:
		// 16-byte model (space-padded) + 2-byte CPU type code.
		payload = make([]byte, 18)
		for i := 0; i < 16; i++ {
			payload[i] = ' '
		}
		copy(payload, "R04ENCPU-SIM")
		binary.LittleEndian.PutUint16(payload[16:18], 0x4612)
	case wire.CmdDeviceReadBatch, wire.CmdDeviceReadRandom:
		payload = []byte{0x34, 0x12, 0x78, 0x56}
	}
	return buildSuccess(req, payload)
}

// buildSuccess emits a 3E-binary response: response subheader,
// routing echoed, data length, end code 0x0000, then payload.
func buildSuccess(req, payload []byte) []byte {
	dataLen := 2 + len(payload) // end code + payload
	out := make([]byte, wire.HeaderLenResponse+2+len(payload))
	binary.LittleEndian.PutUint16(out[0:2], wire.SubheaderResponseLE)
	if len(req) >= wire.HeaderLenRequest {
		copy(out[2:7], req[2:7]) // network / PC / module-IO / station
	} else {
		out[3] = 0xFF
		binary.LittleEndian.PutUint16(out[4:6], 0x03FF)
	}
	// #nosec G115 -- payload is a small canned blob; dataLen fits uint16.
	binary.LittleEndian.PutUint16(out[7:9], uint16(dataLen))
	binary.LittleEndian.PutUint16(out[9:11], 0x0000) // end code = success
	copy(out[11:], payload)
	return out
}
