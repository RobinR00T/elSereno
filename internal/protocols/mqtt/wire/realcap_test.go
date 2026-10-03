package wire_test

import (
	"bytes"
	"testing"

	"local/elsereno/internal/protocols/mqtt/wire"
)

// TestReadConnack_RealCapture validates ReadPacket + ParseConnack against a
// real MQTT CONNACK, byte for byte from pradeesi/MQTT-Wireshark-Capture
// mqtt_packets_tcpdump.pcap: 20 02 00 00 = CONNACK, remaining length 2,
// flags 0x00, return code 0x00 (connection accepted, i.e. the broker let the
// anonymous CONNECT through, which is the exposure the probe reports).
func TestReadConnack_RealCapture(t *testing.T) {
	raw := []byte{0x20, 0x02, 0x00, 0x00}
	b0, payload, err := wire.ReadPacket(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("ReadPacket on a real CONNACK: %v", err)
	}
	if b0>>4 != wire.PktCONNACK {
		t.Errorf("packet type = %d, want CONNACK (%d)", b0>>4, wire.PktCONNACK)
	}
	sessionPresent, code, ok := wire.ParseConnack(payload)
	if !ok {
		t.Fatal("ParseConnack ok=false on a real CONNACK")
	}
	if sessionPresent {
		t.Error("sessionPresent = true, want false")
	}
	if code != 0 {
		t.Errorf("return code = %d, want 0 (accepted)", code)
	}
}
