package wire

import (
	"encoding/binary"
	"errors"
	"io"
)

// DLMS COSEM APDU tag catalogue used by the offensive write
// gate (v1.57). The fingerprint plugin (v1.21 chunk 3) needed
// only AARQ + AARE; offensive gating needs the full set so the
// gate can classify any frame the client sends.
//
// APDU tags are BER application-class tags. Per IEC 62056-53
// (Green Book §5.2):
//
//	0x60  AARQ                  Association Request
//	0x61  AARE                  Association Response
//	0x62  RLRQ                  Release Request
//	0x63  RLRE                  Release Response
//	0xC0  GET-Request           read attribute(s)
//	0xC1  SET-Request           write attribute(s)
//	0xC2  EVENT-Notification    server-pushed (rare from client)
//	0xC3  ACTION-Request        invoke method
//	0xC4  GET-Response
//	0xC5  SET-Response
//	0xC7  ACTION-Response
//	0xD8  EXCEPTION-Response
//
// The "ciphered" variants (GLO_GET_REQUEST 0xC8 etc.) wrap an
// inner APDU with authentication-encryption. They're refused by
// this gate at the APDU-tag level — fine-grained gating inside
// a ciphered APDU requires the operator's master key, which we
// don't have. Operators who need ciphered SET allowlisting can
// run the proxy ahead of the cipher layer (e.g., on the
// management workstation) instead of inline.
const (
	APDUTagAARQ          byte = 0x60
	APDUTagAARE          byte = 0x61
	APDUTagRLRQ          byte = 0x62
	APDUTagRLRE          byte = 0x63
	APDUTagGetRequest    byte = 0xC0
	APDUTagSetRequest    byte = 0xC1
	APDUTagActionRequest byte = 0xC3
	APDUTagGetResponse   byte = 0xC4
	APDUTagSetResponse   byte = 0xC5
	APDUTagActionResp    byte = 0xC7
	APDUTagException     byte = 0xD8
)

// CosemTarget captures the (class-id, OBIS instance-id,
// attribute-or-method-id) tuple extracted from a SET-Request or
// ACTION-Request. The same shape works for both — SET targets an
// attribute, ACTION targets a method, and the byte at the same
// offset distinguishes them (operator-meaningful via the APDU
// tag).
type CosemTarget struct {
	// ClassID is the 16-bit COSEM class identifier.
	// Examples: 1 = Data, 3 = Register, 7 = Profile generic,
	// 8 = Clock, 17 = Script table, 70 = Disconnect Control,
	// 64 = Association LN.
	ClassID uint16
	// OBIS is the 6-byte OBIS instance identifier
	// (A.B.C.D.E.F). 255 in any byte is the wildcard.
	OBIS [6]byte
	// MemberID is the 8-bit attribute-id (SET-Request) or
	// method-id (ACTION-Request).
	MemberID byte
}

// Frame captures a single parsed DLMS wrapper + APDU off the
// wire. Convenient for forwarding without reconstruction.
type Frame struct {
	// Raw is the verbatim wire bytes (8-byte wrapper + APDU).
	Raw []byte
	// SourceWPort echoes the wrapper field.
	SourceWPort uint16
	// DestWPort echoes the wrapper field.
	DestWPort uint16
	// APDU is the BER-encoded COSEM APDU (everything after the
	// 8-byte wrapper).
	APDU []byte
	// APDUTag is the first byte of APDU (the application-class
	// tag).
	APDUTag byte
}

// Stream-parser sentinels.
var (
	// ErrAPDUTooShort means the APDU body declared by the
	// wrapper is shorter than required for the operation
	// (e.g., a SET-Request body shorter than 13 bytes).
	ErrAPDUTooShort = errors.New("dlms: APDU shorter than required for operation")
	// ErrAPDUNotSetRequest means the APDU tag isn't 0xC1.
	ErrAPDUNotSetRequest = errors.New("dlms: APDU tag is not SET-Request (0xC1)")
	// ErrAPDUNotActionRequest means the APDU tag isn't 0xC3.
	ErrAPDUNotActionRequest = errors.New("dlms: APDU tag is not ACTION-Request (0xC3)")
	// ErrAPDUUnknownChoice means the SET/ACTION CHOICE byte
	// isn't 0x01 (normal). Datablock + with-list variants need
	// per-element parsing.
	ErrAPDUUnknownChoice = errors.New("dlms: SET/ACTION CHOICE not 0x01 (only set/action-request-normal supported)")
)

// ReadFrame reads a single DLMS wrapper + APDU off r. Buffers
// the full wrapper (8 bytes) + the APDU body of declared
// length. Errors fall into:
//
//   - io.EOF / io.ErrUnexpectedEOF if the stream closes mid-frame
//   - ErrBadWrapperVersion if the wrapper version isn't 0x0001
//
// The function is conservative: any structural problem returns
// an error which the gate uses to terminate the session.
func ReadFrame(r io.Reader) (Frame, error) {
	hdr := make([]byte, WrapperLen)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return Frame{}, err
	}
	if binary.BigEndian.Uint16(hdr[0:2]) != WrapperVersion {
		return Frame{}, ErrBadWrapperVersion
	}
	apduLen := int(binary.BigEndian.Uint16(hdr[6:8]))
	if apduLen == 0 {
		return Frame{}, ErrAPDUTooShort
	}
	apdu := make([]byte, apduLen)
	if _, err := io.ReadFull(r, apdu); err != nil {
		return Frame{}, err
	}
	raw := make([]byte, WrapperLen+apduLen)
	copy(raw[:WrapperLen], hdr)
	copy(raw[WrapperLen:], apdu)
	return Frame{
		Raw:         raw,
		SourceWPort: binary.BigEndian.Uint16(hdr[2:4]),
		DestWPort:   binary.BigEndian.Uint16(hdr[4:6]),
		APDU:        apdu,
		APDUTag:     apdu[0],
	}, nil
}

// IsAlwaysSafeAPDU reports whether the APDU is part of the
// association lifecycle (AARQ/AARE/RLRQ/RLRE) or is a read
// (GET-Request). These pass without an allowlist entry.
func IsAlwaysSafeAPDU(tag byte) bool {
	switch tag {
	case APDUTagAARQ, APDUTagAARE, APDUTagRLRQ, APDUTagRLRE,
		APDUTagGetRequest, APDUTagGetResponse,
		APDUTagSetResponse, APDUTagActionResp,
		APDUTagException:
		return true
	}
	return false
}

// ParseSetRequest extracts the CosemTarget from a SET-Request
// APDU. Only the set-request-normal CHOICE (0x01) is supported.
// The byte layout (post-tag):
//
//	0xC1 0x01 INVOKE_ID
//	  CLASS_ID(2 BE) OBIS(6) ATTR_ID(1)
//	  ...
//
// So target bytes live at apdu[3..12].
func ParseSetRequest(apdu []byte) (CosemTarget, error) {
	if len(apdu) < 1 {
		return CosemTarget{}, ErrAPDUTooShort
	}
	if apdu[0] != APDUTagSetRequest {
		return CosemTarget{}, ErrAPDUNotSetRequest
	}
	return parseAttributeDescriptor(apdu)
}

// ParseActionRequest extracts the CosemTarget from an
// ACTION-Request APDU. Only the action-request-normal CHOICE
// (0x01) is supported. The byte layout is identical to
// SET-Request except the last byte is a method-id rather than
// attribute-id; CosemTarget.MemberID captures both.
func ParseActionRequest(apdu []byte) (CosemTarget, error) {
	if len(apdu) < 1 {
		return CosemTarget{}, ErrAPDUTooShort
	}
	if apdu[0] != APDUTagActionRequest {
		return CosemTarget{}, ErrAPDUNotActionRequest
	}
	return parseAttributeDescriptor(apdu)
}

// parseAttributeDescriptor walks the bytes shared by SET and
// ACTION-Request normal CHOICE.
func parseAttributeDescriptor(apdu []byte) (CosemTarget, error) {
	// Need: tag(1) + choice(1) + invoke(1) + classID(2) +
	//       OBIS(6) + memberID(1) = 12 bytes minimum.
	const minDescriptorLen = 12
	if len(apdu) < minDescriptorLen {
		return CosemTarget{}, ErrAPDUTooShort
	}
	if apdu[1] != 0x01 {
		return CosemTarget{}, ErrAPDUUnknownChoice
	}
	classID := binary.BigEndian.Uint16(apdu[3:5])
	var obis [6]byte
	copy(obis[:], apdu[5:11])
	return CosemTarget{
		ClassID:  classID,
		OBIS:     obis,
		MemberID: apdu[11],
	}, nil
}

// FormatOBIS renders a 6-byte OBIS code in the canonical
// "A-B:C.D.E*F" form per IEC 62056-61 §3. Convenience helper
// for refusal logs and operator-facing notes.
//
// Common OBIS codes:
//
//	0-0:0.0.0*255  — Logical Device Name
//	0-0:42.0.0*255 — COSEM logical device name
//	0-0:43.0.0*255 — Security Setup
//	1-0:94.7.0*255 — Tariff register class 7
//	0-0:96.50.0*255 — Disconnect Control object (DESTRUCTIVE)
//	0-0:96.10.5*255 — Firmware Identifier
func FormatOBIS(obis [6]byte) string {
	return obisHelper(obis)
}

// obisHelper renders a 6-byte OBIS as canonical "A-B:C.D.E*F"
// using a stack buffer + manual decimal conversion to avoid the
// fmt.Sprintf allocation on the gate's hot path (every refused
// frame logs the OBIS).
func obisHelper(obis [6]byte) string {
	var b [32]byte
	pos := 0
	pos += writeDecimalUint8(b[pos:], obis[0])
	b[pos] = '-'
	pos++
	pos += writeDecimalUint8(b[pos:], obis[1])
	b[pos] = ':'
	pos++
	pos += writeDecimalUint8(b[pos:], obis[2])
	b[pos] = '.'
	pos++
	pos += writeDecimalUint8(b[pos:], obis[3])
	b[pos] = '.'
	pos++
	pos += writeDecimalUint8(b[pos:], obis[4])
	b[pos] = '*'
	pos++
	pos += writeDecimalUint8(b[pos:], obis[5])
	return string(b[:pos])
}

// writeDecimalUint8 writes v as decimal ASCII into buf, returning
// bytes written. Caller-supplied buf must have at least 3 bytes.
func writeDecimalUint8(buf []byte, v byte) int {
	const digits = "0123456789"
	switch {
	case v >= 100:
		buf[0] = digits[v/100]
		buf[1] = digits[(v/10)%10]
		buf[2] = digits[v%10]
		return 3
	case v >= 10:
		buf[0] = digits[v/10]
		buf[1] = digits[v%10]
		return 2
	default:
		buf[0] = digits[v]
		return 1
	}
}
