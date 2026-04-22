// Package wire parses and serialises OPC UA TCP transport-layer
// messages (OPC-UA Part 6 §7.1). Higher-level UA SecureChannel /
// session messages sit above this layer; the fingerprint probe
// only needs Hello / Acknowledge / Error, so that's all this
// package covers for v1.1.
//
// All integers on the wire are little-endian.
package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// MessageType is the 3-byte ASCII header (per OPC-UA Part 6
// Table 27). Only the three we need for the handshake are
// enumerated; MSG / OPN / CLO / RHE frames are rejected with a
// typed error so the caller can note "responded UA but not
// with a HEL/ACK/ERR framing".
type MessageType string

// OPC UA TCP message types we inspect.
const (
	MessageHello   MessageType = "HEL"
	MessageAck     MessageType = "ACK"
	MessageError   MessageType = "ERR"
	MessageOpen    MessageType = "OPN" // OpenSecureChannel
	MessageMessage MessageType = "MSG" // secure-channel body (service request/response)
	MessageClose   MessageType = "CLO" // CloseSecureChannel
)

// ChunkType is the fourth header byte: 'F' (final), 'C' (chunk),
// 'A' (abort). HEL/ACK/ERR are always final.
type ChunkType byte

// Chunk type values.
const (
	ChunkFinal    ChunkType = 'F'
	ChunkContinue ChunkType = 'C'
	ChunkAbort    ChunkType = 'A'
)

// HeaderSize is the common 8-byte prefix every UA TCP message
// carries: 3-byte type + 1-byte chunk + 4-byte LE total length.
const HeaderSize = 8

// MaxMessageSize bounds what we'll allocate for a single UA TCP
// message. Anything larger is treated as malformed — it protects
// the scanner against a hostile server advertising a 4 GiB frame.
const MaxMessageSize = 1 << 20 // 1 MiB

// ErrShortHeader is returned by ParseHeader when fewer than 8
// bytes are available.
var ErrShortHeader = errors.New("opcua/wire: short header")

// ErrBadChunkType covers chunk bytes outside {F, C, A}.
var ErrBadChunkType = errors.New("opcua/wire: bad chunk type")

// ErrOversize is returned when the length prefix exceeds
// MaxMessageSize.
var ErrOversize = errors.New("opcua/wire: oversized message")

// ErrUnknownType is returned when the three-byte magic is not
// one of the recognised UA TCP types.
var ErrUnknownType = errors.New("opcua/wire: unknown message type")

// Header is the parsed 8-byte prefix.
type Header struct {
	Type   MessageType
	Chunk  ChunkType
	Length uint32 // total message size including the 8-byte header
}

// ParseHeader decodes the 8-byte prefix and validates the chunk
// byte + length ceiling. It does NOT require the full message to
// be present — callers probe for the header first, then read the
// remaining Length-HeaderSize bytes.
func ParseHeader(b []byte) (Header, error) {
	if len(b) < HeaderSize {
		return Header{}, ErrShortHeader
	}
	var h Header
	h.Type = MessageType(b[0:3])
	h.Chunk = ChunkType(b[3])
	h.Length = binary.LittleEndian.Uint32(b[4:8])
	switch h.Chunk {
	case ChunkFinal, ChunkContinue, ChunkAbort:
	default:
		return h, fmt.Errorf("%w: 0x%02x", ErrBadChunkType, byte(h.Chunk))
	}
	if h.Length > MaxMessageSize {
		return h, fmt.Errorf("%w: length=%d max=%d", ErrOversize, h.Length, MaxMessageSize)
	}
	switch h.Type {
	case MessageHello, MessageAck, MessageError,
		MessageOpen, MessageMessage, MessageClose:
	default:
		return h, fmt.Errorf("%w: %q", ErrUnknownType, string(h.Type))
	}
	return h, nil
}

// Hello is the client → server handshake message. The endpoint
// URL is the resource identifier the client wants to talk to
// (e.g. "opc.tcp://plc.example:4840").
type Hello struct {
	Version        uint32
	ReceiveBufSize uint32
	SendBufSize    uint32
	MaxMessageSize uint32
	MaxChunkCount  uint32
	EndpointURL    string
}

// EncodeHello renders a minimal HEL message. Buffer/message limits
// match what `open62541` uses by default (64 KiB × 64 KiB × 16 MiB
// × 5000 chunks); any reasonable server accepts these.
func EncodeHello(h Hello) []byte {
	// Body: 20 bytes fixed + 4 bytes URL length + URL payload.
	urlBytes := []byte(h.EndpointURL)
	body := make([]byte, 24+len(urlBytes))
	binary.LittleEndian.PutUint32(body[0:4], h.Version)
	binary.LittleEndian.PutUint32(body[4:8], h.ReceiveBufSize)
	binary.LittleEndian.PutUint32(body[8:12], h.SendBufSize)
	binary.LittleEndian.PutUint32(body[12:16], h.MaxMessageSize)
	binary.LittleEndian.PutUint32(body[16:20], h.MaxChunkCount)
	// OPC UA strings are length-prefixed i32; -1 (0xFFFFFFFF)
	// signals null. We always have a value so just emit the
	// byte length.
	binary.LittleEndian.PutUint32(body[20:24], uint32(len(urlBytes))) //nolint:gosec // G115 — EndpointURL length bounded by caller's input
	copy(body[24:], urlBytes)
	return wrap(MessageHello, body)
}

// Acknowledge is the server → client reply to Hello. The four
// uint32 fields constrain the rest of the session; ElSereno's
// probe doesn't continue past ACK so they're informational only.
type Acknowledge struct {
	Version        uint32
	ReceiveBufSize uint32
	SendBufSize    uint32
	MaxMessageSize uint32
	MaxChunkCount  uint32
}

// ParseAcknowledge decodes an ACK body (everything after the
// 8-byte header). Returns an error if the body is shorter than
// the five-field fixed layout.
func ParseAcknowledge(body []byte) (Acknowledge, error) {
	if len(body) < 20 {
		return Acknowledge{}, fmt.Errorf("opcua/wire: short ACK body: %d bytes", len(body))
	}
	return Acknowledge{
		Version:        binary.LittleEndian.Uint32(body[0:4]),
		ReceiveBufSize: binary.LittleEndian.Uint32(body[4:8]),
		SendBufSize:    binary.LittleEndian.Uint32(body[8:12]),
		MaxMessageSize: binary.LittleEndian.Uint32(body[12:16]),
		MaxChunkCount:  binary.LittleEndian.Uint32(body[16:20]),
	}, nil
}

// Error is the server → client rejection message. ReasonLen may
// be 0 (null reason) or a plain UTF-8 length-prefix.
type Error struct {
	Code   uint32 // OPC UA StatusCode (see Part 6 Annex A)
	Reason string
}

// ParseError decodes an ERR body. The body layout is:
//
//	[0:4]   error code (uint32 LE)
//	[4:8]   reason string length (int32 LE; -1 means null)
//	[8:]    reason string (UTF-8)
//
// If the length prefix is -1 (0xFFFFFFFF) or zero, Reason is "".
func ParseError(body []byte) (Error, error) {
	if len(body) < 8 {
		return Error{}, fmt.Errorf("opcua/wire: short ERR body: %d bytes", len(body))
	}
	code := binary.LittleEndian.Uint32(body[0:4])
	lenField := int32(binary.LittleEndian.Uint32(body[4:8])) //nolint:gosec // G115 — UA wire format uses signed i32 here
	if lenField <= 0 {
		return Error{Code: code}, nil
	}
	if len(body[8:]) < int(lenField) {
		return Error{Code: code}, fmt.Errorf("opcua/wire: truncated ERR reason: want %d have %d",
			lenField, len(body[8:]))
	}
	return Error{Code: code, Reason: string(body[8 : 8+lenField])}, nil
}

// wrap prepends the 8-byte UA TCP header onto body.
func wrap(t MessageType, body []byte) []byte {
	out := make([]byte, HeaderSize+len(body))
	copy(out[0:3], string(t))
	out[3] = byte(ChunkFinal)
	binary.LittleEndian.PutUint32(out[4:8], uint32(HeaderSize+len(body))) //nolint:gosec // G115 — body length bounded by caller
	copy(out[HeaderSize:], body)
	return out
}

// WellKnown UA service-request Binary TypeIds from Part 4
// Annex A. Request NodeIds are numeric in Namespace 0. We only
// enumerate the ones the write-gate distinguishes; the full
// catalogue is 150+ services and adds no value here.
//
// Encoded on the wire as a FourByteNodeId (0x01 encoding byte +
// 1-byte namespace + 2-byte identifier LE). Some stacks use
// TwoByteNodeId for small identifiers; the handler accepts both.
const (
	// TypeIDOpenSecureChannelRequest — OPC-UA Part 4 §7.1.
	TypeIDOpenSecureChannelRequest uint16 = 446
	// TypeIDCloseSecureChannelRequest — Part 4 §7.2.
	TypeIDCloseSecureChannelRequest uint16 = 452
	// TypeIDCreateSessionRequest — Part 4 §7.3.
	TypeIDCreateSessionRequest uint16 = 461
	// TypeIDActivateSessionRequest — Part 4 §7.5.
	TypeIDActivateSessionRequest uint16 = 467
	// TypeIDCloseSessionRequest — Part 4 §7.6.
	TypeIDCloseSessionRequest uint16 = 473
	// TypeIDReadRequest — Part 4 §10.2.
	TypeIDReadRequest uint16 = 631
	// TypeIDWriteRequest — Part 4 §10.4. THE BIG ONE.
	TypeIDWriteRequest uint16 = 673
	// TypeIDCallRequest — Part 4 §11.2. Method invocation can
	// mutate server state as aggressively as Write, so the
	// gate treats it the same.
	TypeIDCallRequest uint16 = 704
	// TypeIDBrowseRequest — Part 4 §8.2.
	TypeIDBrowseRequest uint16 = 527
)

// NodeIDEncoding enumerates the four-variant TypeId encoding
// prefix byte on the wire (Part 6 §5.2.2.9). Only Two- and
// Four-byte numeric variants are used for service TypeIds in
// Namespace 0; the rest (Numeric, String, Guid, ByteString)
// appear for application NodeIds.
type NodeIDEncoding byte

// NodeId encoding prefixes.
const (
	NodeIDTwoByte    NodeIDEncoding = 0x00
	NodeIDFourByte   NodeIDEncoding = 0x01
	NodeIDNumeric    NodeIDEncoding = 0x02
	NodeIDString     NodeIDEncoding = 0x03
	NodeIDGuid       NodeIDEncoding = 0x04
	NodeIDByteString NodeIDEncoding = 0x05
)

// ErrShortMSG is returned when a MSG body is too short to carry
// the SymmetricAlgorithmSecurityHeader + SequenceHeader + TypeId.
var ErrShortMSG = errors.New("opcua/wire: short MSG body")

// ServiceTypeID decodes the service-request TypeId from the
// beginning of a MSG chunk body. A MSG body layout is:
//
//	[0..3]   SecureChannelId (u32)                          — caller can stash
//	[4..7]   TokenId (u32)                                  — caller can stash
//	[8..11]  SequenceNumber (u32)
//	[12..15] RequestId (u32)
//	[16..]   ExpandedNodeId (NodeId encoding + payload)
//	[...]    service-specific body
//
// For OPN the security header is different (AsymmetricAlgorithm
// SecurityHeader with policy URI + certs) so this helper does
// NOT apply; MSG bodies only. Returns (0, false) when the TypeId
// encoding is not a FourByte or TwoByte numeric — those are the
// only forms service requests use.
func ServiceTypeID(msgBody []byte) (uint16, bool) {
	if len(msgBody) < 17 {
		return 0, false
	}
	enc := NodeIDEncoding(msgBody[16])
	switch enc { //nolint:exhaustive // Numeric/String/Guid/ByteString are for application NodeIds; service TypeIds use only Two/FourByte
	case NodeIDTwoByte:
		// [17] = identifier (u8)
		if len(msgBody) < 18 {
			return 0, false
		}
		return uint16(msgBody[17]), true
	case NodeIDFourByte:
		// [17]   = namespace (u8; must be 0 for spec services)
		// [18:20] = identifier (u16 LE)
		if len(msgBody) < 20 {
			return 0, false
		}
		if msgBody[17] != 0 {
			return 0, false
		}
		return binary.LittleEndian.Uint16(msgBody[18:20]), true
	}
	return 0, false
}

// IsMutatingService returns true when the given TypeId names a
// service request that can mutate server state. Write + Call
// are the canonical two; AddNodes / AddReferences / DeleteNodes
// / DeleteReferences mutate the address-space itself and would
// matter for an operator with full admin rights, but ElSereno's
// gate surface is Write + Call because those are what exploit
// attempts reach for. Address-space mutations land with v1.3.
func IsMutatingService(typeID uint16) bool {
	switch typeID {
	case TypeIDWriteRequest, TypeIDCallRequest:
		return true
	}
	return false
}
