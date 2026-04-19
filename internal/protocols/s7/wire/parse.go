package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// TPKTHeaderLen is the fixed TPKT envelope size.
const TPKTHeaderLen = 4

// TPKTVersion is the RFC 1006 version byte.
const TPKTVersion uint8 = 0x03

// MaxTPKTLen caps the envelope so adversarial servers cannot force
// unbounded reads.
const MaxTPKTLen uint16 = 65535

// MinTPKTLen is 4 header bytes + 3 COTP LI+type+param.
const MinTPKTLen uint16 = 7

// COTP PDU types (high nibble of byte 1 after LI).
const (
	COTPConnectionRequest byte = 0xE0
	COTPConnectionConfirm byte = 0xD0
	COTPDisconnectRequest byte = 0x80
	COTPData              byte = 0xF0
	COTPExpeditedData     byte = 0x10
)

// ErrBadTPKT is returned when the TPKT header is malformed.
var ErrBadTPKT = errors.New("s7: bad TPKT")

// ErrShortCOTP is returned when the COTP portion is shorter than the
// length indicator claims.
var ErrShortCOTP = errors.New("s7: short COTP")

// TPKT is the decoded envelope.
type TPKT struct {
	Version uint8
	Length  uint16
	Payload []byte // bytes that follow the 4-byte header (COTP + S7)
}

// ParseTPKT parses b into TPKT. It does not copy Payload; callers
// must treat the slice as read-only.
func ParseTPKT(b []byte) (TPKT, error) {
	if len(b) < TPKTHeaderLen {
		return TPKT{}, fmt.Errorf("%w: %d bytes", ErrBadTPKT, len(b))
	}
	t := TPKT{
		Version: b[0],
		Length:  binary.BigEndian.Uint16(b[2:4]),
	}
	if t.Version != TPKTVersion {
		return TPKT{}, fmt.Errorf("%w: version 0x%02x", ErrBadTPKT, t.Version)
	}
	if t.Length < MinTPKTLen {
		return TPKT{}, fmt.Errorf("%w: length=%d", ErrBadTPKT, t.Length)
	}
	if int(t.Length) > len(b) {
		return TPKT{}, fmt.Errorf("%w: length=%d, have %d", ErrBadTPKT, t.Length, len(b))
	}
	t.Payload = b[TPKTHeaderLen:t.Length]
	return t, nil
}

// ReadTPKT reads one complete TPKT envelope from r.
func ReadTPKT(r io.Reader) (TPKT, error) {
	var hdr [TPKTHeaderLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return TPKT{}, fmt.Errorf("s7: header: %w", err)
	}
	length := binary.BigEndian.Uint16(hdr[2:4])
	if length < MinTPKTLen {
		return TPKT{}, fmt.Errorf("%w: length=%d", ErrBadTPKT, length)
	}
	payload := make([]byte, length-TPKTHeaderLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return TPKT{}, fmt.Errorf("s7: payload: %w", err)
	}
	return TPKT{Version: hdr[0], Length: length, Payload: payload}, nil
}

// WriteTPKT writes an envelope with the given COTP+S7 payload.
func WriteTPKT(w io.Writer, payload []byte) error {
	total := TPKTHeaderLen + len(payload)
	if total > int(MaxTPKTLen) {
		return fmt.Errorf("%w: %d bytes", ErrBadTPKT, total)
	}
	// #nosec G115 -- bounded above
	length := uint16(total)
	var hdr [TPKTHeaderLen]byte
	hdr[0] = TPKTVersion
	binary.BigEndian.PutUint16(hdr[2:4], length)
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// COTPType returns the COTP PDU type byte from a TPKT payload.
// Returns (0, false) if the payload is too short.
func COTPType(payload []byte) (byte, bool) {
	if len(payload) < 2 {
		return 0, false
	}
	return payload[1] & 0xF0, true
}

// IsCOTPConfirm reports whether payload starts with a COTP
// Connection Confirm PDU.
func IsCOTPConfirm(payload []byte) bool {
	t, ok := COTPType(payload)
	return ok && t == COTPConnectionConfirm
}

// BuildCOTPConnectionRequest returns the COTP CR bytes that follow
// the TPKT header. TSAPs are the usual "0x0100" (source) and
// "0x0102" (destination rack 0, slot 2) used for S7-300/400.
func BuildCOTPConnectionRequest() []byte {
	return []byte{
		0x11,       // LI (length indicator), bytes that follow
		0xE0,       // CR
		0x00, 0x00, // DstRef
		0x00, 0x01, // SrcRef
		0x00, // Class 0
		// Source TSAP parameter: code=0xC1, len=2, 0x01 0x00
		0xC1, 0x02, 0x01, 0x00,
		// Destination TSAP parameter: code=0xC2, len=2, 0x01 0x02
		0xC2, 0x02, 0x01, 0x02,
		// TPDU size parameter: code=0xC0, len=1, 0x0A (1024 bytes)
		0xC0, 0x01, 0x0A,
	}
}
