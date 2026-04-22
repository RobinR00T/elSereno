// Package wire parses the IAX2 (Inter-Asterisk eXchange v2,
// RFC 5456) frame subset ElSereno probes. IAX2 is Asterisk's
// native binary UDP protocol on port 4569; signalling + media
// share the same stream.
//
// The probe sends a `NEW` full frame and looks for any full-
// frame reply — an ACCEPT means the remote accepted our
// proposed call (which we immediately HANGUP), AUTHREQ means
// it wants authentication (the server is alive and in
// production use), REJECT or HANGUP mean it's alive but
// refused us. Any of these is positive confirmation that the
// remote speaks IAX2.
//
// Frame format (full frame, RFC 5456 §8.1.1):
//
//	0                   1                   2                   3
//	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|F|   SrcCallNum      |R|    DstCallNum     |                  |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+   Timestamp   |
//	|                                                              |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|    OSeqno     |    ISeqno     |  FrameType   | C |   Subclass |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                     Information Elements                      |
//	...
//
// F=1 = full frame (control). FrameType + Subclass tell us what
// kind of control message — IAX (0x06) + NEW (0x01) is the
// canonical probe.
package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// HeaderLen is the fixed size of a full-frame IAX2 header (12 bytes).
const HeaderLen = 12

// ErrTooShort is returned when the byte slice is shorter than
// the full-frame header.
var ErrTooShort = errors.New("iax2/wire: frame too short")

// ErrMiniFrame is returned when the frame's high bit is 0
// (mini-frame, audio). Probes deal with full frames only.
var ErrMiniFrame = errors.New("iax2/wire: mini-frame (audio), not a control frame")

// FrameType identifies the meta-class of a full-frame body.
type FrameType uint8

// IAX2 frame types (RFC 5456 §8.1.2).
const (
	FrameTypeDTMF    FrameType = 0x01
	FrameTypeVoice   FrameType = 0x02
	FrameTypeVideo   FrameType = 0x03
	FrameTypeControl FrameType = 0x04
	FrameTypeNull    FrameType = 0x05
	FrameTypeIAX     FrameType = 0x06
	FrameTypeText    FrameType = 0x07
	FrameTypeImage   FrameType = 0x08
	FrameTypeHTML    FrameType = 0x09
	FrameTypeCNG     FrameType = 0x0A
)

// IAXSubclass identifies an IAX-specific control message (only
// applicable when FrameType == FrameTypeIAX).
type IAXSubclass uint8

// IAX subclasses (RFC 5456 §8.6). Only the ones the probe + the
// vendor inspector care about are enumerated.
const (
	IAXNew     IAXSubclass = 0x01 // call setup
	IAXPing    IAXSubclass = 0x02
	IAXPong    IAXSubclass = 0x03
	IAXAck     IAXSubclass = 0x04
	IAXHangup  IAXSubclass = 0x05
	IAXReject  IAXSubclass = 0x06
	IAXAccept  IAXSubclass = 0x07
	IAXAuthReq IAXSubclass = 0x08
	IAXAuthRep IAXSubclass = 0x09
	IAXInval   IAXSubclass = 0x0A
	IAXLagRq   IAXSubclass = 0x0B
	IAXLagRp   IAXSubclass = 0x0C
	IAXRegreq  IAXSubclass = 0x0D
	IAXRegauth IAXSubclass = 0x0E
	IAXRegack  IAXSubclass = 0x0F
	IAXRegrej  IAXSubclass = 0x10
	IAXRegrel  IAXSubclass = 0x11
)

// Header is the parsed 12-byte full-frame prefix.
type Header struct {
	// SrcCallNum is the 15-bit source call number (issued by
	// the sender).
	SrcCallNum uint16
	// DstCallNum is the 15-bit destination call number (0 for
	// NEW; assigned by the callee).
	DstCallNum uint16
	// Timestamp is the 32-bit millisecond timestamp.
	Timestamp uint32
	// OSeqno / ISeqno are the outbound/inbound sequence
	// numbers (1 byte each).
	OSeqno, ISeqno uint8
	// FrameType + Subclass classify the body.
	FrameType FrameType
	Subclass  uint8
}

// ParseHeader decodes the 12-byte full-frame header. Returns
// ErrMiniFrame if the high bit of byte 0 is 0 (mini-frame).
func ParseHeader(b []byte) (Header, error) {
	if len(b) < HeaderLen {
		return Header{}, fmt.Errorf("%w: %d bytes", ErrTooShort, len(b))
	}
	if b[0]&0x80 == 0 {
		return Header{}, ErrMiniFrame
	}
	return Header{
		SrcCallNum: binary.BigEndian.Uint16(b[0:2]) & 0x7FFF,
		DstCallNum: binary.BigEndian.Uint16(b[2:4]) & 0x7FFF,
		Timestamp:  binary.BigEndian.Uint32(b[4:8]),
		OSeqno:     b[8],
		ISeqno:     b[9],
		FrameType:  FrameType(b[10]),
		Subclass:   b[11],
	}, nil
}

// IsIAXReply returns true when the header is an IAX-class
// frame. The probe accepts any IAX reply as positive
// confirmation; callers may further inspect `Subclass`.
func (h Header) IsIAXReply() bool {
	return h.FrameType == FrameTypeIAX
}

// BuildNEW crafts a minimal NEW frame announcing a probe call.
// Information Elements omitted — most Asterisk deployments
// will accept a bare NEW and respond (with AUTHREQ or REJECT)
// even without DNID/CALLEDCONTEXT IEs.
//
// `srcCall` is the caller-assigned 15-bit call number; use a
// random value per probe to avoid the remote thinking it's a
// retransmission.
func BuildNEW(srcCall uint16) []byte {
	buf := make([]byte, HeaderLen)
	// byte 0: F=1 + high 7 bits of SrcCallNum.
	// (15-bit SrcCallNum fits in buf[0:2] with the F bit set
	// in the high position.)
	binary.BigEndian.PutUint16(buf[0:2], 0x8000|(srcCall&0x7FFF))
	// DstCallNum = 0 on NEW. R bit = 0.
	binary.BigEndian.PutUint16(buf[2:4], 0)
	// Timestamp = 0 (peers don't strictly require a real one
	// for the first frame).
	binary.BigEndian.PutUint32(buf[4:8], 0)
	buf[8] = 0 // OSeqno = 0
	buf[9] = 0 // ISeqno = 0
	buf[10] = byte(FrameTypeIAX)
	buf[11] = byte(IAXNew)
	return buf
}

// BuildHANGUP crafts a HANGUP frame paired with an existing
// source+dest call number. Used by the probe to terminate the
// call cleanly if the remote accepted.
func BuildHANGUP(srcCall, dstCall uint16, oseqno, iseqno uint8) []byte {
	buf := make([]byte, HeaderLen)
	binary.BigEndian.PutUint16(buf[0:2], 0x8000|(srcCall&0x7FFF))
	binary.BigEndian.PutUint16(buf[2:4], dstCall&0x7FFF)
	binary.BigEndian.PutUint32(buf[4:8], 0)
	buf[8] = oseqno
	buf[9] = iseqno
	buf[10] = byte(FrameTypeIAX)
	buf[11] = byte(IAXHangup)
	return buf
}
