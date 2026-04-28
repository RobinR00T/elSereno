// Package wire implements the minimum subset of DLMS/COSEM over
// TCP needed for read-only fingerprinting on TCP/4059. The
// on-wire layout is from IEC 62056-46 (Green Book §8.4 — DLMS
// Wrapper) and IEC 62056-53 (COSEM application layer).
//
// This package implements ONLY the request builder + response
// classifier for **AARQ** (Application Association Request) —
// the canonical "associate with me" handshake. The AARE
// (Application Association Response) carries an
// association-result code that fingerprints the server. No
// GET-Request / SET-Request / ACTION-Request services are
// implemented; v1.21 chunk 3 is read-only by design.
package wire

import (
	"encoding/binary"
	"errors"
)

// DLMS Wrapper layout (IEC 62056-46 §8.4):
//
//	Offset  Field        Size  Description
//	0..1    Version      2     0x0001 BE
//	2..3    SourceWPort  2     BE — typically 0x0001 (mgmt) or 0x0010 (US)
//	4..5    DestWPort    2     BE — typically 0x0001 (server mgmt logical device)
//	6..7    Length       2     BE — APDU length in bytes
//	8+      APDU         …     BER-encoded COSEM APDU
const (
	// WrapperVersion is the canonical DLMS wrapper version.
	WrapperVersion uint16 = 0x0001
	// WrapperLen is the 8-byte wrapper header length.
	WrapperLen = 8
	// SourceWPortClient is the wPort the client sends from
	// (Public Client management endpoint).
	SourceWPortClient uint16 = 0x0010
	// DestWPortServer is the wPort the client targets (Server
	// Management Logical Device).
	DestWPortServer uint16 = 0x0001

	// AARQTag is the BER tag for AARQ-PDU [APPLICATION 0] IMPLICIT.
	AARQTag byte = 0x60
	// AARETag is the BER tag for AARE-PDU [APPLICATION 1] IMPLICIT.
	AARETag byte = 0x61
)

// Sentinel errors so callers can distinguish parser-failure
// classes (drives the "why did this not fingerprint" surface on
// the dashboard).
var (
	// ErrShortFrame means the response is shorter than the 8-byte
	// wrapper header.
	ErrShortFrame = errors.New("dlms: response shorter than wrapper header")
	// ErrBadWrapperVersion means the wrapper version is not
	// 0x0001.
	ErrBadWrapperVersion = errors.New("dlms: wrapper version not 0x0001")
	// ErrLengthMismatch means the wrapper Length field disagrees
	// with the actual APDU body size.
	ErrLengthMismatch = errors.New("dlms: wrapper length disagrees with APDU body size")
	// ErrNotAARE means the APDU's first byte is not 0x61
	// (AARE-PDU tag).
	ErrNotAARE = errors.New("dlms: APDU first byte not AARE-PDU tag (0x61)")
)

// AssociationInfo captures the parsed AARE header.
type AssociationInfo struct {
	// SourceWPort echoes the wrapper SourceWPort from the
	// response (server's management endpoint).
	SourceWPort uint16
	// DestWPort echoes the wrapper DestWPort.
	DestWPort uint16
	// APDULen is the length of the AARE APDU (from wrapper
	// Length field).
	APDULen uint16
}

// canonicalMinimalAARQ is a 29-byte AARQ APDU that requests the
// Logical Name referencing application context with no
// ciphering (OID 2.16.756.5.8.1.1) and a minimal
// initiate-request user-information block.
//
// Frame breakdown:
//
//	60 1B                          AARQ-PDU [APPLICATION 0] IMPLICIT, len 27
//	A1 09                          application-context-name [1] EXPLICIT
//	  06 07 60 85 74 05 08 01 01     OID = 2.16.756.5.8.1.1 (LN_NoCiphering)
//	BE 0E                          user-information [APPLICATION 30] EXPLICIT
//	  04 0C                          OCTET STRING, len 12
//	    01                             InitiateRequest tag
//	    00 00 00                       dedicated-key + response-allowed + proposed-quality-of-service (omitted)
//	    06                             proposed-DLMS-version-number (6)
//	    5F 1F 04 00 00 18 1F           proposed-conformance bit-string
var canonicalMinimalAARQ = []byte{
	0x60, 0x1B,
	0xA1, 0x09,
	0x06, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x01, 0x01,
	0xBE, 0x0E,
	0x04, 0x0C,
	0x01,
	0x00, 0x00, 0x00,
	0x06,
	0x5F, 0x1F, 0x04, 0x00, 0x00, 0x18, 0x1F,
}

// AARQAPDULen is the length of the canonical minimal AARQ APDU
// (29 bytes — see canonicalMinimalAARQ).
const AARQAPDULen = 29

// BuildAARQ crafts a 37-byte DLMS-wrapper-framed AARQ probe:
// 8-byte wrapper header + 29-byte canonical minimal AARQ APDU.
// The wrapper uses Source=0x0010 (Public Client management) and
// Dest=0x0001 (Server management logical device) — the canonical
// default endpoints for unauthenticated probes.
func BuildAARQ() []byte {
	frame := make([]byte, WrapperLen+AARQAPDULen)
	binary.BigEndian.PutUint16(frame[0:2], WrapperVersion)
	binary.BigEndian.PutUint16(frame[2:4], SourceWPortClient)
	binary.BigEndian.PutUint16(frame[4:6], DestWPortServer)
	binary.BigEndian.PutUint16(frame[6:8], AARQAPDULen)
	copy(frame[WrapperLen:], canonicalMinimalAARQ)
	return frame
}

// ClassifyResponse validates that a candidate response has the
// DLMS wrapper shape (version 0x0001 + length consistent + AARE
// tag). On any structural error the appropriate sentinel is
// returned. On success the AssociationInfo header is populated.
func ClassifyResponse(buf []byte) (AssociationInfo, error) {
	if len(buf) < WrapperLen+1 {
		return AssociationInfo{}, ErrShortFrame
	}
	if binary.BigEndian.Uint16(buf[0:2]) != WrapperVersion {
		return AssociationInfo{}, ErrBadWrapperVersion
	}
	apduLen := binary.BigEndian.Uint16(buf[6:8])
	if int(apduLen)+WrapperLen != len(buf) {
		return AssociationInfo{}, ErrLengthMismatch
	}
	if buf[WrapperLen] != AARETag {
		return AssociationInfo{}, ErrNotAARE
	}
	return AssociationInfo{
		SourceWPort: binary.BigEndian.Uint16(buf[2:4]),
		DestWPort:   binary.BigEndian.Uint16(buf[4:6]),
		APDULen:     apduLen,
	}, nil
}

// IsWrapperResponse returns true iff the buffer's first 2 bytes
// match the DLMS wrapper version (0x0001) and the buffer is at
// least header-sized. Useful for the "responded but not the
// AARE shape we wanted" branch.
func IsWrapperResponse(buf []byte) bool {
	if len(buf) < WrapperLen {
		return false
	}
	return binary.BigEndian.Uint16(buf[0:2]) == WrapperVersion
}
