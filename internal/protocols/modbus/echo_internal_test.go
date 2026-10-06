package modbus

import (
	"net"
	"testing"
	"time"

	"local/elsereno/internal/protocols/modbus/wire"
)

// TestProbeStageEchoIsNotModbus: a reflected Read Coils request parses as a
// successful FC1 reply (same function code), and used to be noted
// "read-coils accepted". Modbus scoring is constant, so the note is the only
// thing that could lie about it (PITF-071).
func TestProbeStageEchoIsNotModbus(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	go func() {
		defer func() { _ = server.Close() }()
		// Read the whole request frame (WriteFrame may split MBAP and PDU
		// across writes on an unbuffered pipe), then reflect it.
		req, err := wire.ReadFrame(server)
		if err != nil {
			return
		}
		_ = wire.WriteFrame(server, req)
	}()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	note, vendor, _, _ := probeStage(client)
	if note != "reply echoes the probe (not Modbus)" {
		t.Fatalf("note = %q, want the echo note", note)
	}
	if vendor != "" {
		t.Fatalf("vendor = %q, want none (FC43 must not run against a reflector)", vendor)
	}
}

// TestProbeStageRealReadCoilsReply: a genuine FC1 reply (byte count + coil
// status) is still noted as accepted, so the echo check does not swallow it.
func TestProbeStageRealReadCoilsReply(t *testing.T) {
	t.Parallel()
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	go func() {
		defer func() { _ = server.Close() }()
		if _, err := wire.ReadFrame(server); err != nil {
			return
		}
		// MBAP txID 0x0001, protocol 0, length 4 (unit + FC + count + status),
		// unit 0x01; PDU 01 01 01 (FC1, 1 byte, coil on).
		_, _ = server.Write([]byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x04, 0x01, 0x01, 0x01, 0x01})
	}()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	note, _, _, _ := probeStage(client)
	if note != "read-coils accepted" {
		t.Fatalf("note = %q, want %q", note, "read-coils accepted")
	}
}
