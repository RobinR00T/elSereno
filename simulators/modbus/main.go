// Command modbus-sim is a minimal Modbus/TCP responder for the
// integration suite. It implements the read-only FCs (1, 2, 3, 4)
// against a tiny in-memory bank and rejects writes with
// IllegalFunction, so tests cannot mutate the simulator's state even
// if the product code accidentally lets a write through.
//
// Operators who want a full-featured PLC simulator should use
// pymodbus (installed via `pipx install pymodbus[repl]` — see the F3
// protocol doc). This Go responder exists so every CI run, including
// those without network access to PyPI, has a deterministic peer.
package main

import (
	"context"
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"local/elsereno/internal/protocols/modbus/wire"
)

// state is the minimal in-memory bank the simulator serves. All
// four address spaces share a single 65536-coil / 65536-register
// layout; FC 1 / 2 index coils, FC 3 / 4 index registers.
type state struct {
	coils     [65536]bool
	registers [65536]uint16
}

func main() {
	os.Exit(runMain())
}

func runMain() int {
	listen := flag.String("listen", "127.0.0.1:1502", "bind address")
	seed := flag.Int("seed", 0, "seed (unused in F3; reserved for chaos mode)")
	flag.Parse()
	_ = seed

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	lc := &net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", *listen)
	if err != nil {
		log.Printf("listen %s: %v", *listen, err)
		return 1
	}
	defer func() { _ = ln.Close() }()
	log.Printf("modbus-sim listening on %s", *listen)

	s := &state{}
	// Plant a simple pattern so Read Coils/Registers return something
	// other than zeros.
	for i := 0; i < 32; i++ {
		s.coils[i] = i%2 == 0
		s.registers[i] = uint16(i * 10) // #nosec G115 -- i < 32
	}

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
		go serve(ctx, conn, s)
	}
}

func serve(ctx context.Context, conn net.Conn, s *state) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	for {
		if ctx.Err() != nil {
			return
		}
		frame, err := wire.ReadFrame(conn)
		if err != nil {
			return
		}
		resp := respond(frame, s)
		if err := wire.WriteFrame(conn, resp); err != nil {
			return
		}
	}
}

func respond(req wire.Frame, s *state) wire.Frame {
	switch req.FunctionCode() {
	case wire.FCReadCoils, wire.FCReadDiscreteInputs:
		return replyCoils(req, s)
	case wire.FCReadHoldingRegisters, wire.FCReadInputRegisters:
		return replyRegisters(req, s)
	case wire.FCEncapsulatedInterface:
		return replyDeviceID(req)
	default:
		return exceptionResp(req, wire.ExIllegalFunction)
	}
}

func exceptionResp(req wire.Frame, code wire.ExceptionCode) wire.Frame {
	fc := uint8(req.FunctionCode()) | 0x80
	return wire.Frame{
		MBAP: wire.MBAP{TxID: req.MBAP.TxID, Unit: req.MBAP.Unit},
		PDU:  []byte{fc, uint8(code)},
	}
}

func replyCoils(req wire.Frame, s *state) wire.Frame {
	// PDU: [FC][start hi][start lo][count hi][count lo]. Coils and
	// discrete inputs share the same in-memory bank — the simulator
	// is deliberately minimal.
	if len(req.PDU) < 5 {
		return exceptionResp(req, wire.ExIllegalDataValue)
	}
	start := uint16(req.PDU[1])<<8 | uint16(req.PDU[2])
	count := uint16(req.PDU[3])<<8 | uint16(req.PDU[4])
	if count == 0 || count > 2000 {
		return exceptionResp(req, wire.ExIllegalDataValue)
	}
	byteCount := (count + 7) / 8
	out := make([]byte, 0, 2+byteCount)
	out = append(out, req.PDU[0], byte(byteCount)) // #nosec G115 -- byteCount <= 250
	data := make([]byte, byteCount)
	for i := uint16(0); i < count; i++ {
		if s.coils[start+i] {
			data[i/8] |= 1 << (i % 8)
		}
	}
	out = append(out, data...)
	return wire.Frame{MBAP: req.MBAP, PDU: out}
}

func replyRegisters(req wire.Frame, s *state) wire.Frame {
	if len(req.PDU) < 5 {
		return exceptionResp(req, wire.ExIllegalDataValue)
	}
	start := uint16(req.PDU[1])<<8 | uint16(req.PDU[2])
	count := uint16(req.PDU[3])<<8 | uint16(req.PDU[4])
	if count == 0 || count > 125 {
		return exceptionResp(req, wire.ExIllegalDataValue)
	}
	byteCount := count * 2
	out := make([]byte, 0, 2+byteCount)
	out = append(out, req.PDU[0], byte(byteCount)) // #nosec G115 -- byteCount <= 250
	for i := uint16(0); i < count; i++ {
		v := s.registers[start+i]
		out = append(out, byte(v>>8), byte(v&0xff))
	}
	return wire.Frame{MBAP: req.MBAP, PDU: out}
}

// replyDeviceID returns a fixed FC 43/14 basic (0x01) response.
func replyDeviceID(req wire.Frame) wire.Frame {
	if len(req.PDU) < 4 || req.PDU[1] != 0x0E {
		return exceptionResp(req, wire.ExIllegalDataValue)
	}
	// PDU: FC, MEI=0x0E, conformity=0x01, more=0, nextObj=0, numObjs=3
	//      obj0 (vendor)="ElSereno", obj1 (product)="modbus-sim",
	//      obj2 (revision)="v1"
	pdu := []byte{
		byte(wire.FCEncapsulatedInterface), 0x0E,
		0x01, 0x00, 0x00, 0x03,
	}
	for id, v := range map[byte]string{0x00: "ElSereno", 0x01: "modbus-sim", 0x02: "v1"} {
		pdu = append(pdu, id, byte(len(v))) // #nosec G115 -- string lengths bounded
		pdu = append(pdu, []byte(v)...)
	}
	return wire.Frame{MBAP: req.MBAP, PDU: pdu}
}
