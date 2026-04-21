package wire_test

import (
	"encoding/binary"
	"errors"
	"testing"

	"local/elsereno/internal/protocols/opcua/wire"
)

func TestEncodeHello_RoundTripsThroughHeader(t *testing.T) {
	payload := wire.EncodeHello(wire.Hello{
		Version:        0,
		ReceiveBufSize: 65536,
		SendBufSize:    65536,
		MaxMessageSize: 16777216,
		MaxChunkCount:  5000,
		EndpointURL:    "opc.tcp://plc.example:4840",
	})
	h, err := wire.ParseHeader(payload)
	if err != nil {
		t.Fatal(err)
	}
	if h.Type != wire.MessageHello {
		t.Fatalf("type = %q", h.Type)
	}
	if h.Chunk != wire.ChunkFinal {
		t.Fatalf("chunk = %q", string(h.Chunk))
	}
	if int(h.Length) != len(payload) {
		t.Fatalf("length header = %d, actual = %d", h.Length, len(payload))
	}
}

func TestParseAcknowledge_ExtractsFields(t *testing.T) {
	// Build an ACK by hand: header + 20 bytes of fixed fields.
	body := make([]byte, 20)
	binary.LittleEndian.PutUint32(body[0:4], 0)
	binary.LittleEndian.PutUint32(body[4:8], 8192)
	binary.LittleEndian.PutUint32(body[8:12], 8192)
	binary.LittleEndian.PutUint32(body[12:16], 65536)
	binary.LittleEndian.PutUint32(body[16:20], 4)
	ack, err := wire.ParseAcknowledge(body)
	if err != nil {
		t.Fatal(err)
	}
	if ack.ReceiveBufSize != 8192 {
		t.Fatalf("recv = %d", ack.ReceiveBufSize)
	}
	if ack.MaxChunkCount != 4 {
		t.Fatalf("max chunk = %d", ack.MaxChunkCount)
	}
}

func TestParseError_HandlesNullReason(t *testing.T) {
	body := make([]byte, 8)
	binary.LittleEndian.PutUint32(body[0:4], 0x80000000)
	binary.LittleEndian.PutUint32(body[4:8], 0xFFFFFFFF) // length = -1 (null)
	e, err := wire.ParseError(body)
	if err != nil {
		t.Fatal(err)
	}
	if e.Code != 0x80000000 {
		t.Fatalf("code = 0x%08x", e.Code)
	}
	if e.Reason != "" {
		t.Fatalf("reason = %q, want empty for null", e.Reason)
	}
}

func TestParseError_HandlesUTF8Reason(t *testing.T) {
	reason := "Bad_Server_State"
	body := make([]byte, 8+len(reason))
	binary.LittleEndian.PutUint32(body[0:4], 0x80af0000)
	// #nosec G115 — reason literal fits uint32
	binary.LittleEndian.PutUint32(body[4:8], uint32(len(reason)))
	copy(body[8:], reason)
	e, err := wire.ParseError(body)
	if err != nil {
		t.Fatal(err)
	}
	if e.Reason != reason {
		t.Fatalf("reason = %q, want %q", e.Reason, reason)
	}
}

func TestParseHeader_RejectsBadChunk(t *testing.T) {
	// Valid HEL magic + invalid chunk byte 'X'.
	b := []byte{'H', 'E', 'L', 'X', 0x08, 0, 0, 0}
	_, err := wire.ParseHeader(b)
	if !errors.Is(err, wire.ErrBadChunkType) {
		t.Fatalf("want ErrBadChunkType, got %v", err)
	}
}

func TestParseHeader_RejectsOversize(t *testing.T) {
	b := []byte{'H', 'E', 'L', 'F'}
	// Length larger than MaxMessageSize — 0xFFFFFFFF = ~4 GiB.
	b = append(b, 0xFF, 0xFF, 0xFF, 0xFF)
	_, err := wire.ParseHeader(b)
	if !errors.Is(err, wire.ErrOversize) {
		t.Fatalf("want ErrOversize, got %v", err)
	}
}

func TestParseHeader_RejectsShort(t *testing.T) {
	_, err := wire.ParseHeader([]byte{'H', 'E', 'L'})
	if !errors.Is(err, wire.ErrShortHeader) {
		t.Fatalf("want ErrShortHeader, got %v", err)
	}
}

func TestParseHeader_RejectsUnknownType(t *testing.T) {
	// Valid chunk + length, unknown type "XYZ".
	b := make([]byte, wire.HeaderSize)
	copy(b[0:3], "XYZ")
	b[3] = 'F'
	binary.LittleEndian.PutUint32(b[4:8], wire.HeaderSize)
	_, err := wire.ParseHeader(b)
	if !errors.Is(err, wire.ErrUnknownType) {
		t.Fatalf("want ErrUnknownType, got %v", err)
	}
}
