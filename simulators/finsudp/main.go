package main

import (
	"context"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"local/elsereno/internal/protocols/finsudp/wire"
)

func main() {
	os.Exit(run())
}

// run is the testable body of main so the deferred cancel stays
// intact before os.Exit on the outermost caller.
func run() int {
	addr := flag.String("addr", "127.0.0.1:9600", "listen address (UDP)")
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	lc := net.ListenConfig{}
	pc, err := lc.ListenPacket(ctx, "udp", *addr)
	if err != nil {
		log.Println("fins-sim: listen:", err)
		return 1
	}
	defer func() { _ = pc.Close() }()
	log.Printf("fins-sim: listening on %s (udp)", *addr)

	go func() {
		<-ctx.Done()
		_ = pc.Close()
	}()

	buf := make([]byte, 2048)
	for {
		n, raddr, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return 0
			}
			log.Printf("read: %v", err)
			continue
		}
		resp := respond(buf[:n])
		if resp == nil {
			continue
		}
		if _, err := pc.WriteTo(resp, raddr); err != nil {
			log.Printf("write: %v", err)
		}
	}
}

// respond builds a success FINS response for a request datagram, or
// nil if the request is too short to echo. The routing bytes are
// swapped (response addressed back to the caller) and the end code is
// 0x0000 (success). Command-specific payloads make the fingerprint
// path work: CONTROLLER DATA READ returns a model, MEMORY AREA READ a
// small data blob.
func respond(req []byte) []byte {
	cmd, ok := wire.ExtractCommand(req)
	if !ok {
		return nil
	}
	var data []byte
	switch cmd {
	case wire.CmdControllerDataRead:
		// 20-byte model + 20-byte internal code (space-padded ASCII).
		data = make([]byte, 40)
		for i := range data {
			data[i] = ' '
		}
		copy(data, "CJ2M-CPU33")
		copy(data[20:], "V1.04 ELSERENO-SIM")
	case wire.CmdMemoryAreaRead, wire.CmdMemoryAreaMultipleRead:
		data = []byte{0x12, 0x34}
	default:
		// Other commands: success with no payload.
	}
	return buildSuccess(req, data)
}

// buildSuccess emits a FINS response: ICF response, routing swapped,
// SID + MRC/SRC echoed, end code 0x0000, then payload.
func buildSuccess(req, data []byte) []byte {
	out := make([]byte, 0, wire.HeaderLen+4+len(data))
	out = append(out, wire.ICFResponse, 0x00, 0x02)
	out = append(out, req[6], req[7], req[8]) // DNA/DA1/DA2 <- req source
	out = append(out, req[3], req[4], req[5]) // SNA/SA1/SA2 <- req dest
	out = append(out, req[9])                 // SID echo
	out = append(out, req[wire.HeaderLen], req[wire.HeaderLen+1])
	out = append(out, 0x00, 0x00) // end code = success
	out = append(out, data...)
	return out
}
