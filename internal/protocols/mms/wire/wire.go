// Package wire implements the minimum subset of IEC 61850 MMS
// (Manufacturing Message Specification, ISO 9506) needed for
// read-only fingerprinting on TCP/102. MMS is the application-
// layer protocol every IEC 61850-8-1 substation device speaks
// (protection relays, RTUs, merging units, station controllers).
//
// Port 102 is shared with Siemens S7 — both wrap their PDUs in
// TPKT (RFC 1006) + ISO 8073 COTP. The disambig point is the
// TSAP (Transport Service Access Point) selectors carried in
// the COTP Connect-Request:
//
//   - **S7-300/400/1500** uses source TSAP `01 00` and
//     destination TSAP `01 02` (rack 0, slot 2).
//   - **IEC 61850 MMS** uses source TSAP `00 01` and
//     destination TSAP `00 01` (the canonical MMS server TSAP).
//
// The MMS plugin sends a COTP-CR with the MMS TSAPs; an upstream
// that responds with COTP-CC has accepted the MMS handshake at
// the transport layer, which is a positive identification at
// reasonable confidence. Higher-confidence MMS detection (full
// ACSE A-ASSOCIATE-REQUEST with the IEC 61850-8-1 application-
// context name OID 1.0.9506.2.3) is a future tightening — the
// COTP-layer disambig is sufficient to distinguish MMS from S7
// on shared-port-102 deployments.
//
// This package implements ONLY the TPKT envelope read/write +
// the MMS-specific COTP Connect-Request builder + a response
// classifier. The full MMS service-request layer (Read /
// GetVariableAccessAttributes / etc.) is out of scope for v1.25.
//
// No service-request frames are issued; v1.25 is read-only by
// design.
package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// TPKTHeaderLen is the fixed TPKT envelope size (RFC 1006 §6).
const TPKTHeaderLen = 4

// TPKTVersion is the RFC 1006 version byte at offset 0.
const TPKTVersion uint8 = 0x03

// MaxTPKTLen caps the envelope so adversarial servers can't
// force unbounded reads.
const MaxTPKTLen uint16 = 65535

// MinTPKTLen is the lower bound (4 header + 3 COTP min).
const MinTPKTLen uint16 = 7

// COTP PDU types in the high nibble of byte 1 (after LI).
const (
	// COTPConnectionRequest (CR): client → server initial.
	COTPConnectionRequest byte = 0xE0
	// COTPConnectionConfirm (CC): server → client accept.
	COTPConnectionConfirm byte = 0xD0
	// COTPDisconnectRequest (DR): server → client refuse.
	COTPDisconnectRequest byte = 0x80
)

// Sentinel errors so callers can distinguish parser-failure
// classes (drives the "why did this not fingerprint" surface
// on the dashboard).
var (
	// ErrBadTPKT means the TPKT header is malformed.
	ErrBadTPKT = errors.New("mms: bad TPKT envelope")
	// ErrShortCOTP means the COTP body is shorter than the LI
	// or PDU type byte requires.
	ErrShortCOTP = errors.New("mms: short COTP body")
	// ErrNotCOTPConfirm means the response is COTP-DR or some
	// other non-CC PDU — the upstream refused our MMS-style
	// TSAPs.
	ErrNotCOTPConfirm = errors.New("mms: COTP did not confirm (likely S7 or non-MMS server on port 102)")
)

// TPKT is the decoded envelope. Payload is the COTP body that
// follows the 4-byte TPKT header.
type TPKT struct {
	Version uint8
	Length  uint16
	Payload []byte
}

// ReadTPKT reads one complete TPKT envelope from r. Bounded by
// MaxTPKTLen so a hostile peer can't drive unbounded allocation.
func ReadTPKT(r io.Reader) (TPKT, error) {
	var hdr [TPKTHeaderLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return TPKT{}, fmt.Errorf("mms: header: %w", err)
	}
	length := binary.BigEndian.Uint16(hdr[2:4])
	if length < MinTPKTLen {
		return TPKT{}, fmt.Errorf("%w: length=%d", ErrBadTPKT, length)
	}
	if length > MaxTPKTLen {
		return TPKT{}, fmt.Errorf("%w: length=%d > max %d", ErrBadTPKT, length, MaxTPKTLen)
	}
	payload := make([]byte, length-TPKTHeaderLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return TPKT{}, fmt.Errorf("mms: payload: %w", err)
	}
	if hdr[0] != TPKTVersion {
		return TPKT{}, fmt.Errorf("%w: version 0x%02x", ErrBadTPKT, hdr[0])
	}
	return TPKT{Version: hdr[0], Length: length, Payload: payload}, nil
}

// WriteTPKT writes an envelope with the given COTP payload. The
// header is computed from len(payload) + 4.
func WriteTPKT(w io.Writer, payload []byte) error {
	total := TPKTHeaderLen + len(payload)
	if total > int(MaxTPKTLen) {
		return fmt.Errorf("%w: %d bytes > max %d", ErrBadTPKT, total, MaxTPKTLen)
	}
	hdr := []byte{TPKTVersion, 0x00, 0x00, 0x00}
	binary.BigEndian.PutUint16(hdr[2:4], uint16(total)) // #nosec G115 -- bounded by MaxTPKTLen guard above
	if _, err := w.Write(hdr); err != nil {
		return fmt.Errorf("mms: write header: %w", err)
	}
	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf("mms: write payload: %w", err)
	}
	return nil
}

// BuildCOTPConnectionRequestMMS returns the COTP CR bytes for an
// IEC 61850 MMS handshake. TSAPs are the canonical MMS server
// values (`00 01` source and destination). TPDU size 1024 bytes.
//
// The frame is binary-stable: an MMS server accepts these
// TSAPs and replies with a COTP-CC (PDU type 0xD0). An S7 server
// rejects these TSAPs with a COTP-DR (PDU type 0x80, reason 1
// "TSAP unknown").
func BuildCOTPConnectionRequestMMS() []byte {
	return []byte{
		0x11,       // LI (length indicator, bytes that follow)
		0xE0,       // PDU type: CR
		0x00, 0x00, // DstRef (zero on initial CR)
		0x00, 0x01, // SrcRef
		0x00, // Class 0
		// Source TSAP: code=0xC1, len=2, value 0x00 0x01 (MMS)
		0xC1, 0x02, 0x00, 0x01,
		// Destination TSAP: code=0xC2, len=2, value 0x00 0x01 (MMS server)
		0xC2, 0x02, 0x00, 0x01,
		// TPDU size: code=0xC0, len=1, 0x0A (1024 bytes)
		0xC0, 0x01, 0x0A,
	}
}

// IsCOTPConfirm returns true iff the COTP payload's PDU-type
// byte (offset 1, after the LI) is COTPConnectionConfirm (0xD0).
// A CC means the server accepted our MMS-style TSAPs at the
// transport layer.
func IsCOTPConfirm(buf []byte) bool {
	return len(buf) >= 2 && buf[1] == COTPConnectionConfirm
}

// IsCOTPDisconnect returns true iff the COTP payload's PDU-type
// byte is COTPDisconnectRequest (0x80). A DR means the server
// rejected our TSAPs — the upstream is on port 102 but is
// almost certainly S7 (or another vendor-specific server) that
// doesn't accept the MMS TSAPs.
func IsCOTPDisconnect(buf []byte) bool {
	return len(buf) >= 2 && buf[1] == COTPDisconnectRequest
}

// ClassifyCOTP returns a short note describing the COTP response
// class, with sentinel errors for non-COTP responses. Used by
// the plugin to differentiate "MMS confirmed" from "non-MMS
// server on port 102".
func ClassifyCOTP(buf []byte) (string, error) {
	if len(buf) < 2 {
		return "", ErrShortCOTP
	}
	switch {
	case IsCOTPConfirm(buf):
		return "MMS COTP confirm", nil
	case IsCOTPDisconnect(buf):
		return "", ErrNotCOTPConfirm
	default:
		return "", fmt.Errorf("%w: PDU type 0x%02x", ErrShortCOTP, buf[1])
	}
}
