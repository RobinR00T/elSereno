// Command dnp3-sim is a minimal DNP3/TCP outstation for the demo and
// integration suite, plus a `-send` client mode that emits correctly
// CRC-framed request frames so the demo does not hand-craft wire bytes.
//
// As an outstation it reads link frames, logs the application function
// code (and the CROB control points for a control), and answers every
// request with a minimal IIN=0 response. It never acts on a control:
// the write-gated proxy in front of it is what refuses unauthorised
// operations, so anything that reaches this outstation was allowed.
//
// This is not a full IEEE 1815 implementation; it exists so CI has a
// deterministic DNP3 peer without external dependencies.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"local/elsereno/internal/protocols/dnp3/wire"
)

func main() { os.Exit(run()) }

// respIIN1 / respIIN2 are the Internal Indications the outstation
// returns on every response, set from -iin so the demo can exercise the
// proxy's response-path IIN monitor.
var respIIN1, respIIN2 uint8

func run() int {
	listen := flag.String("listen", "127.0.0.1:20000", "outstation bind address")
	send := flag.String("send", "", "client mode: send one frame then exit (read|latch5|trip5|bcast-latch|coldrestart|analog-ok|analog-hi)")
	addr := flag.String("addr", "127.0.0.1:20000", "client mode: target host:port")
	iin := flag.String("iin", "", "outstation IIN to return on every response: restart|trouble|config-corrupt|func-not-supp")
	flag.Parse()

	respIIN1, respIIN2 = parseIINFlag(*iin)
	if *send != "" {
		return sendOne(*send, *addr)
	}
	return serve(*listen)
}

// parseIINFlag maps a -iin name to the (IIN1, IIN2) octets.
func parseIINFlag(name string) (uint8, uint8) {
	switch name {
	case "restart":
		return wire.IIN1DeviceRestart, 0
	case "trouble":
		return wire.IIN1DeviceTrouble, 0
	case "config-corrupt":
		return 0, wire.IIN2ConfigCorrupt
	case "func-not-supp":
		return 0, wire.IIN2FuncNotSupp
	default:
		return 0, 0
	}
}

// --- outstation ---------------------------------------------------

func serve(listen string) int {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	lc := &net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", listen)
	if err != nil {
		log.Printf("listen %s: %v", listen, err)
		return 1
	}
	defer func() { _ = ln.Close() }()
	log.Printf("dnp3-sim outstation listening on %s", listen)
	go func() { <-ctx.Done(); _ = ln.Close() }()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return 0
			}
			continue
		}
		go handle(ctx, conn)
	}
}

func handle(ctx context.Context, conn net.Conn) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	hdr := make([]byte, wire.HeaderLen)
	for {
		if ctx.Err() != nil {
			return
		}
		if _, err := io.ReadFull(conn, hdr); err != nil {
			return
		}
		lh, err := wire.ParseHeader(hdr)
		if err != nil {
			return
		}
		body := make([]byte, wire.BodyLen(lh.Length))
		if len(body) > 0 {
			if _, err := io.ReadFull(conn, body); err != nil {
				return
			}
		}
		apdu, ok := wire.StripBlockCRCs(body, int(lh.Length)-5)
		if !ok {
			log.Printf("received malformed frame (bad block CRC) dest=%d src=%d", lh.Dest, lh.Src)
			continue
		}
		logRequest(lh, apdu)
		if _, err := conn.Write(buildResponse(lh)); err != nil {
			return
		}
	}
}

func logRequest(lh wire.Header, apdu []byte) {
	if len(apdu) < 3 {
		log.Printf("received short frame dest=%d src=%d", lh.Dest, lh.Src)
		return
	}
	fc := apdu[2]
	if wire.AppIsControl(fc) {
		points, ok := wire.ExtractCROBs(apdu[3:])
		log.Printf("received control fc=0x%02x dest=%d src=%d crobs=%v ok=%v", fc, lh.Dest, lh.Src, points, ok)
		return
	}
	log.Printf("received fc=0x%02x dest=%d src=%d", fc, lh.Dest, lh.Src)
}

// buildResponse returns a minimal IIN=0 response addressed back to the
// requesting master, with correct CRCs.
func buildResponse(req wire.Header) []byte {
	userData := []byte{0xC0, 0xC0, 0x81, respIIN1, respIIN2} // transport, AC, FC=response, IIN1, IIN2
	body := wire.AppendBlockCRCs(userData)
	frame := make([]byte, wire.HeaderLen+len(body))
	frame[0], frame[1] = wire.StartBytes[0], wire.StartBytes[1]
	frame[2] = uint8(5 + len(userData)) // #nosec G115 -- fixed 5-byte body
	frame[3] = 0x44                     // PRM=1, FC=4
	frame[4], frame[5] = byte(req.Src&0xFF), byte(req.Src>>8)
	frame[6], frame[7] = byte(req.Dest&0xFF), byte(req.Dest>>8)
	crc := wire.CRC16(frame[0:8])
	frame[8], frame[9] = byte(crc&0xFF), byte(crc>>8)
	copy(frame[wire.HeaderLen:], body)
	return frame
}

// --- client -------------------------------------------------------

func sendOne(kind, addr string) int {
	frame, ok := craft(kind)
	if !ok {
		log.Printf("unknown -send %q", kind)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		log.Printf("dial %s: %v", addr, err)
		return 1
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write(frame); err != nil {
		log.Printf("write: %v", err)
		return 1
	}
	_ = conn.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	buf := make([]byte, 64)
	n, _ := conn.Read(buf)
	fmt.Printf("%x\n", buf[:n])
	return 0
}

// craft builds a correct request frame for the named demo case. Every
// case originates at the master link address (2).
func craft(kind string) ([]byte, bool) {
	const outstation = 1
	switch kind {
	case "read": // FC 1 Read, Class 0 poll (g60v1, all-points)
		return frame(outstation, wire.AppReadCode, []byte{60, 1, 0x06}), true
	case "latch5": // FC 5 Direct Operate, LATCH_ON on point 5
		return frame(outstation, wire.AppDirectOperateCode, crob(5, wire.OpLatchOn)), true
	case "trip5": // FC 5 Direct Operate, TRIP + PULSE_ON on point 5
		return frame(outstation, wire.AppDirectOperateCode, crob(5, 0x81)), true
	case "bcast-latch": // FC 5 to the broadcast address
		return frame(0xFFFF, wire.AppDirectOperateCode, crob(5, wire.OpLatchOn)), true
	case "coldrestart": // FC 0x0D Cold Restart
		return frame(outstation, 0x0D, nil), true
	case "analog-ok": // FC 5 Direct Operate, g41 setpoint 30 on point 10
		return frame(outstation, wire.AppDirectOperateCode, aob(10, 30)), true
	case "analog-hi": // FC 5 Direct Operate, g41 setpoint 90 on point 10
		return frame(outstation, wire.AppDirectOperateCode, aob(10, 90)), true
	default:
		return nil, false
	}
}

// aob builds a single-point g41v1 Analog Output Block (int32 setpoint,
// qualifier 0x17) at index with value v.
func aob(index uint8, v int32) []byte {
	obj := []byte{41, 1, 0x17, 0x01, index}
	var b [4]byte
	// #nosec G115 -- int32 masked into 4 LE octets (sim)
	b[0], b[1], b[2], b[3] = byte(v), byte(v>>8), byte(v>>16), byte(v>>24)
	obj = append(obj, b[:]...)
	return append(obj, 0x00) // control status
}

// crob builds a single-point g12v1 object (qualifier 0x17).
func crob(index, code uint8) []byte {
	obj := []byte{12, 1, 0x17, 0x01, index}
	c := make([]byte, 11)
	c[0] = code
	return append(obj, c...)
}

// frame builds an unconfirmed-user-data request from the master (link
// address 2) to dest, with correct CRCs.
func frame(dest uint16, appFC uint8, objects []byte) []byte {
	const master = 2
	userData := append([]byte{0xC0, 0xC0, appFC}, objects...)
	body := wire.AppendBlockCRCs(userData)
	f := make([]byte, wire.HeaderLen+len(body))
	f[0], f[1] = wire.StartBytes[0], wire.StartBytes[1]
	f[2] = uint8(5 + len(userData)) // #nosec G115 -- demo body bounded
	f[3] = 0xC4
	f[4], f[5] = byte(dest&0xFF), byte(dest>>8)
	f[6], f[7] = master&0xFF, master>>8
	crc := wire.CRC16(f[0:8])
	f[8], f[9] = byte(crc&0xFF), byte(crc>>8)
	copy(f[wire.HeaderLen:], body)
	return f
}
