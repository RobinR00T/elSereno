package wire_test

import (
	"bytes"
	"testing"

	"local/elsereno/internal/protocols/mqtt/wire"
)

func TestEncodeConnectRoundTrips(t *testing.T) {
	pkt := wire.EncodeConnect("elsereno")
	b0, payload, err := wire.ReadPacket(bytes.NewReader(pkt))
	if err != nil {
		t.Fatalf("ReadPacket: %v", err)
	}
	if wire.PacketType(b0) != wire.PktCONNECT {
		t.Fatalf("type = %d, want CONNECT(%d)", wire.PacketType(b0), wire.PktCONNECT)
	}
	// Variable header: 00 04 'M' 'Q' 'T' 'T' 04 02 00 3C ...
	want := []byte{0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x02, 0x00, 0x3C}
	if !bytes.HasPrefix(payload, want) {
		t.Fatalf("CONNECT variable header wrong: % x", payload)
	}
	if !bytes.Contains(payload, []byte("elsereno")) {
		t.Errorf("client id not in payload: % x", payload)
	}
}

func TestParseConnack(t *testing.T) {
	present, code, ok := wire.ParseConnack([]byte{0x00, wire.ConnAccepted})
	if !ok || present || code != wire.ConnAccepted {
		t.Fatalf("got (%t,%d,%t)", present, code, ok)
	}
	if _, _, ok := wire.ParseConnack([]byte{0x00}); ok {
		t.Error("short CONNACK must not parse")
	}
	if wire.ConnackReturnName(wire.ConnRefusedNotAuth) == "" {
		t.Error("missing name for not-authorized")
	}
}

func TestEncodeSubscribeAndSuback(t *testing.T) {
	pkt := wire.EncodeSubscribe(1, "#")
	b0, payload, err := wire.ReadPacket(bytes.NewReader(pkt))
	if err != nil {
		t.Fatalf("ReadPacket: %v", err)
	}
	if wire.PacketType(b0) != wire.PktSUBSCRIBE {
		t.Fatalf("type = %d, want SUBSCRIBE", wire.PacketType(b0))
	}
	if b0&0x0F != 0x02 {
		t.Errorf("SUBSCRIBE fixed-header flags must be 0x02, got 0x%x", b0&0x0F)
	}
	// packetID(2) + topic len(2) + '#' + qos(1).
	if !bytes.Contains(payload, []byte("#")) {
		t.Errorf("topic not in payload: % x", payload)
	}

	// SUBACK: packetID(2) + one granted code.
	granted, ok := wire.ParseSuback([]byte{0x00, 0x01, 0x00})
	if !ok || len(granted) != 1 || granted[0] != 0x00 {
		t.Fatalf("SUBACK parse: granted=%v ok=%t", granted, ok)
	}
}

func TestPublishTopic(t *testing.T) {
	// PUBLISH payload: topic len(2) + topic + payload bytes.
	topic := "spBv1.0/plant/NBIRTH/edge1"
	var payload []byte
	payload = append(payload, byte(len(topic)>>8), byte(len(topic))) // #nosec G115 -- test topic is short
	payload = append(payload, topic...)
	payload = append(payload, 0xDE, 0xAD)
	got, ok := wire.PublishTopic(payload)
	if !ok || got != topic {
		t.Fatalf("PublishTopic = %q,%t want %q", got, ok, topic)
	}
}

func TestReadPacketMultiByteLength(t *testing.T) {
	// A CONNECT with a long client id forces a >127 remaining length,
	// exercising the multi-byte remaining-length codec.
	long := make([]byte, 200)
	for i := range long {
		long[i] = 'a'
	}
	pkt := wire.EncodeConnect(string(long))
	_, payload, err := wire.ReadPacket(bytes.NewReader(pkt))
	if err != nil {
		t.Fatalf("ReadPacket long: %v", err)
	}
	if !bytes.Contains(payload, long) {
		t.Error("long client id not round-tripped through multi-byte length")
	}
}
