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

	"local/elsereno/internal/protocols/opcua/wire"
)

// opcua-sim is a throwaway OPC UA (UA-TCP) stand-in for the write-gate
// demo (scripts/demo-opcua-proxy.sh). It is NOT a real OPC UA server:
// it accepts TCP, reads whatever UA-TCP frames the gated proxy forwards
// (length-prefixed, header at offset 4), logs each MSG service TypeId,
// and answers with a canned MSG. A refused service never reaches here
// (the proxy returns a ServiceFault itself), which is the demo's point.
func main() {
	os.Exit(run())
}

func run() int {
	addr := flag.String("addr", "127.0.0.1:4840", "listen address (TCP)")
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", *addr)
	if err != nil {
		log.Println("opcua-sim: listen:", err)
		return 1
	}
	log.Printf("opcua-sim: listening on %s (tcp)", *addr)

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

// cannedResponse is a 28-byte MSG frame (a stand-in service response).
func cannedResponse() []byte {
	body := make([]byte, 20) // 16-byte secure-channel prefix + FourByteNodeId
	body[16] = 0x01          // FourByteNodeId encoding
	frame := make([]byte, wire.HeaderSize+len(body))
	copy(frame[0:3], "MSG")
	frame[3] = byte(wire.ChunkFinal)
	// #nosec G115 -- total is a fixed 28 bytes.
	binary.LittleEndian.PutUint32(frame[4:8], uint32(len(frame)))
	copy(frame[wire.HeaderSize:], body)
	return frame
}

// readFrame reads one length-prefixed UA-TCP frame: 8-byte header, then
// (Length - 8) body bytes.
func readFrame(conn net.Conn) ([]byte, error) {
	hdr := make([]byte, wire.HeaderSize)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return nil, err
	}
	total := int(binary.LittleEndian.Uint32(hdr[4:8]))
	if total < wire.HeaderSize || total > 1<<20 {
		return nil, errors.New("opcua-sim: implausible frame length")
	}
	frame := make([]byte, total)
	copy(frame, hdr)
	if _, err := io.ReadFull(conn, frame[wire.HeaderSize:]); err != nil {
		return nil, err
	}
	return frame, nil
}

func serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	for {
		_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		frame, err := readFrame(conn)
		if len(frame) > 0 {
			if svc, ok := wire.ServiceTypeID(frame[wire.HeaderSize:]); ok {
				log.Printf("opcua-sim: received MSG service TypeId=%d (%d bytes)", svc, len(frame))
			} else {
				log.Printf("opcua-sim: received %s frame (%d bytes)", string(frame[0:3]), len(frame))
			}
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
