//go:build ignore

// Command gen writes examples/captures/tristation-demo.pcap: a small,
// fully synthetic TriStation session (addresses in 192.0.2.0/24,
// TEST-NET-1; a fictional project "DEMO-SIS") used by docs/EXAMPLES.md.
// Run: go run examples/captures/gen/main.go examples/captures/tristation-demo.pcap
package main

import (
	"encoding/binary"
	"os"

	"local/elsereno/internal/protocols/tristation/wire"
)

func ipv4udp(src, dst byte, sport uint16, payload []byte) []byte {
	u := make([]byte, 8, 8+len(payload))
	binary.BigEndian.PutUint16(u[0:], sport)
	binary.BigEndian.PutUint16(u[2:], 1502)
	binary.BigEndian.PutUint16(u[4:], uint16(8+len(payload)))
	u = append(u, payload...)
	ip := []byte{0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 17, 0, 0, 192, 0, 2, src, 192, 0, 2, dst}
	binary.BigEndian.PutUint16(ip[2:], uint16(20+len(u)))
	return append([]byte{0, 0, 0, 0, 0, dst, 0, 0, 0, 0, 0, src, 0x08, 0x00}, append(ip, u...)...)
}

func connectReply() []byte {
	b := []byte{wire.OpConnectReply, 0, 0, 0}
	return binary.LittleEndian.AppendUint16(b, wire.CRC16(b))
}

// demoStatus builds a CP status response: key PROGRAM, RUNNING, project
// "DEMO-SIS", version 1.4, with a fictional download time. All values
// are invented for the example; no real plant data.
func demoStatus() []byte {
	data := make([]byte, 76) // datagram offsets minus the 14-byte header
	data[7] = 1              // offKeyState 21: PROGRAM
	data[8] = 0              // offRunState 22: RUNNING
	binary.LittleEndian.PutUint16(data[58:], 4)  // offMinor 72
	binary.LittleEndian.PutUint16(data[60:], 1)  // offMajor 74
	binary.LittleEndian.PutUint32(data[62:], 1700000000) // offTimestamp 76
	copy(data[66:], "DEMO-SIS")                  // offProject 80
	b, err := wire.BuildCommand(wire.CmdCPStatusResponse, 0, data)
	if err != nil {
		panic(err)
	}
	return b
}

func main() {
	buf := make([]byte, 24)
	binary.LittleEndian.PutUint32(buf, 0xA1B2C3D4)
	binary.LittleEndian.PutUint16(buf[4:], 2)
	binary.LittleEndian.PutUint32(buf[20:], 1)

	run, _ := wire.BuildCommand(wire.CmdRunProgram, 7, nil)
	frames := []struct {
		t     uint32
		s, d  byte
		sport uint16
		pl    []byte
	}{
		{1700000000, 10, 20, 50000, wire.BuildConnect()},
		{1700000000, 20, 10, 1502, connectReply()},
		{1700000001, 10, 20, 50000, wire.BuildGetCPStatus(0)},
		{1700000001, 20, 10, 1502, demoStatus()},
		{1700000123, 10, 20, 50000, run},
		{1700000124, 10, 20, 50000, wire.BuildDisconnect()},
	}
	for _, f := range frames {
		pkt := ipv4udp(f.s, f.d, f.sport, f.pl)
		rec := make([]byte, 16)
		binary.LittleEndian.PutUint32(rec, f.t)
		binary.LittleEndian.PutUint32(rec[8:], uint32(len(pkt)))
		binary.LittleEndian.PutUint32(rec[12:], uint32(len(pkt)))
		buf = append(buf, rec...)
		buf = append(buf, pkt...)
	}
	if err := os.WriteFile(os.Args[1], buf, 0o644); err != nil {
		panic(err)
	}
}
