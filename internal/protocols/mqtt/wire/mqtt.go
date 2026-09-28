// Package wire encodes and parses the MQTT 3.1.1 (OASIS) control packets
// ElSereno's exposure probe needs: CONNECT / CONNACK (does anonymous
// access work?), SUBSCRIBE / SUBACK (is a wildcard subscription granted?)
// and enough of PUBLISH to read a topic name (Sparkplug B detection).
//
// Only the pre-auth, read-only subset is implemented: the probe never
// PUBLISHes (a write). Reference: MQTT Version 3.1.1, OASIS Standard,
// 29 October 2014.
package wire

import (
	"errors"
	"io"
)

// Control packet types (MQTT 3.1.1 §2.2.1, high nibble of byte 1).
const (
	PktCONNECT   byte = 1
	PktCONNACK   byte = 2
	PktPUBLISH   byte = 3
	PktSUBSCRIBE byte = 8
	PktSUBACK    byte = 9
)

// CONNACK return codes (§3.2.2.3).
const (
	ConnAccepted          byte = 0x00
	ConnRefusedProtocol   byte = 0x01
	ConnRefusedIdentifier byte = 0x02
	ConnRefusedUnavail    byte = 0x03
	ConnRefusedBadAuth    byte = 0x04
	ConnRefusedNotAuth    byte = 0x05
)

// SubackFailure is the SUBACK return code meaning the subscription was
// refused (§3.9.3).
const SubackFailure byte = 0x80

// ConnackReturnName renders a CONNACK return code for findings.
func ConnackReturnName(code byte) string {
	switch code {
	case ConnAccepted:
		return "Accepted"
	case ConnRefusedProtocol:
		return "Refused: unacceptable protocol version"
	case ConnRefusedIdentifier:
		return "Refused: identifier rejected"
	case ConnRefusedUnavail:
		return "Refused: server unavailable"
	case ConnRefusedBadAuth:
		return "Refused: bad user name or password"
	case ConnRefusedNotAuth:
		return "Refused: not authorized"
	default:
		return "Refused: unknown code"
	}
}

// putString appends an MQTT UTF-8 string: 2-byte big-endian length then
// the bytes (§1.5.3).
func putString(b []byte, s string) []byte {
	n := len(s)
	b = append(b, byte(n>>8), byte(n)) // #nosec G115 -- MQTT string; protocol strings here are short
	return append(b, s...)
}

// encodeRemainingLength appends the variable-length Remaining Length
// field (§2.2.3). Values above 268435455 are not produced here.
func encodeRemainingLength(b []byte, n int) []byte {
	for {
		d := byte(n % 128) // #nosec G115 -- n%128 is 0-127, always fits a byte
		n /= 128
		if n > 0 {
			d |= 0x80
		}
		b = append(b, d)
		if n == 0 {
			return b
		}
	}
}

// EncodeConnect builds an anonymous, clean-session MQTT 3.1.1 CONNECT
// with the given client identifier: no username, no password, no will.
// A broker that answers CONNACK 0x00 to this allows anonymous access.
func EncodeConnect(clientID string) []byte {
	var vh []byte
	vh = putString(vh, "MQTT")  // protocol name
	vh = append(vh, 0x04)       // protocol level 4 = 3.1.1
	vh = append(vh, 0x02)       // connect flags: Clean Session only
	vh = append(vh, 0x00, 0x3C) // keep-alive 60s
	vh = putString(vh, clientID)

	out := []byte{PktCONNECT << 4}
	out = encodeRemainingLength(out, len(vh))
	return append(out, vh...)
}

// EncodeSubscribe builds a SUBSCRIBE for a single topic filter at QoS 0.
// SUBSCRIBE requires the fixed-header flags nibble to be 0b0010 (§3.8.1).
func EncodeSubscribe(packetID uint16, topic string) []byte {
	var vh []byte
	vh = append(vh, byte(packetID>>8), byte(packetID)) // #nosec G115 -- 16-bit packet id split into two bytes
	vh = putString(vh, topic)
	vh = append(vh, 0x00) // requested QoS 0

	out := []byte{PktSUBSCRIBE<<4 | 0x02}
	out = encodeRemainingLength(out, len(vh))
	return append(out, vh...)
}

var (
	// ErrShort means the buffer ended before a field completed.
	ErrShort = errors.New("mqtt/wire: short packet")
	// ErrMalformedLength means the Remaining Length field was invalid.
	ErrMalformedLength = errors.New("mqtt/wire: malformed remaining length")
)

// maxPacket bounds a single read so a hostile broker cannot drive a huge
// allocation. Probe traffic is tiny.
const maxPacket = 1 << 20

// ReadPacket reads one control packet from r and returns its first byte
// (type<<4 | flags) and the remaining-length-delimited payload.
func ReadPacket(r io.Reader) (b0 byte, payload []byte, err error) {
	var one [1]byte
	if _, err = io.ReadFull(r, one[:]); err != nil {
		return 0, nil, err
	}
	b0 = one[0]
	rem, err := readRemainingLength(r)
	if err != nil {
		return 0, nil, err
	}
	if rem < 0 || rem > maxPacket {
		return 0, nil, ErrMalformedLength
	}
	payload = make([]byte, rem)
	if rem > 0 {
		if _, err = io.ReadFull(r, payload); err != nil {
			return 0, nil, err
		}
	}
	return b0, payload, nil
}

// readRemainingLength decodes the variable-length field (§2.2.3), at most
// 4 bytes.
func readRemainingLength(r io.Reader) (int, error) {
	var value int
	var one [1]byte
	for i := 0; i < 4; i++ {
		if _, err := io.ReadFull(r, one[:]); err != nil {
			return 0, err
		}
		value += int(one[0]&0x7f) * pow128(i)
		if one[0]&0x80 == 0 {
			return value, nil
		}
	}
	return 0, ErrMalformedLength
}

// pow128 returns 128**i for i in 0..3 (the MQTT remaining-length
// multipliers), avoiding a math import.
func pow128(i int) int {
	m := 1
	for ; i > 0; i-- {
		m *= 128
	}
	return m
}

// PacketType returns the control packet type (high nibble of b0).
func PacketType(b0 byte) byte { return b0 >> 4 }

// ParseConnack decodes a CONNACK payload (§3.2): 1 byte acknowledge
// flags + 1 byte return code.
func ParseConnack(payload []byte) (sessionPresent bool, returnCode byte, ok bool) {
	if len(payload) < 2 {
		return false, 0, false
	}
	return payload[0]&0x01 != 0, payload[1], true
}

// ParseSuback decodes a SUBACK payload (§3.9): 2-byte packet identifier
// then one return code per subscribed topic. Returns the return codes.
func ParseSuback(payload []byte) (returnCodes []byte, ok bool) {
	if len(payload) < 3 {
		return nil, false
	}
	return payload[2:], true
}

// PublishTopic extracts the topic name from a PUBLISH payload. The topic
// is the first field of the variable header regardless of QoS (the packet
// identifier that follows it for QoS>0 is not needed here). Used to spot
// the Sparkplug B namespace.
func PublishTopic(payload []byte) (string, bool) {
	if len(payload) < 2 {
		return "", false
	}
	n := int(payload[0])<<8 | int(payload[1])
	if 2+n > len(payload) {
		return "", false
	}
	return string(payload[2 : 2+n]), true
}
