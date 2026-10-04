package wire_test

import (
	"bytes"
	"testing"

	"local/elsereno/internal/protocols/mqtt/wire"
)

// FuzzReadPacket asserts the MQTT packet reader and the payload parsers
// never panic on arbitrary bytes off TCP/1883. ReadPacket decodes the MQTT
// remaining-length varint (attacker-controlled, a classic over-read /
// allocation hazard), and the CONNACK / SUBACK / PUBLISH parsers then run on
// the payload. Seeded with a real CONNACK (0x20 0x02 0x00 0x00) and a
// well-formed CONNECT.
func FuzzReadPacket(f *testing.F) {
	f.Add([]byte{0x20, 0x02, 0x00, 0x00}) // real CONNACK, accepted
	f.Add(wire.EncodeConnect("probe"))
	f.Add([]byte{})
	f.Add([]byte{0x30, 0xff, 0xff, 0xff, 0x7f}) // max 4-byte remaining-length varint, no body
	f.Fuzz(func(_ *testing.T, b []byte) {
		b0, payload, err := wire.ReadPacket(bytes.NewReader(b))
		if err != nil {
			return
		}
		_ = wire.PacketType(b0)
		_, _, _ = wire.ParseConnack(payload)
		_, _ = wire.ParseSuback(payload)
		_, _ = wire.PublishTopic(payload)
	})
}
