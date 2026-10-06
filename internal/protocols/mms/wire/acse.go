// ACSE A-ASSOCIATE-REQUEST builder + response classifier.
// v1.51 chunk 1.
//
// IEC 61850-8-1 §A.2 specifies the OSI session + presentation +
// ACSE association procedure that MMS clients use to bind to a
// substation IED. The full stack (top-down):
//
//   ACSE AARQ                                  ← what we're building
//     application-context-name = 1.0.9506.2.3
//     user-information[Association-info[Initiate-RequestPDU]]
//   ISO 8823 Presentation CP-PPDU
//   ISO 8327 Session CONNECT SPDU
//   COTP DT (TSDU)                             ← already in TPKT
//   TPKT envelope                              ← already in TPKT
//
// The AARQ is the real client request of the w3h/icsmaster IEC 61850
// MMS captures (iec61850_read.pcap, iec61850_get_name_list.pcap: the
// same bytes in both), which the server there accepts (AARE result 0).
// The response (AARE) carries the same application-context OID echoed
// back, which is what we look for to distinguish "real MMS server" from
// "anything else that happens to handshake COTP".
//
// Until 2026-10-07 this file shipped a hand-written AARQ whose
// user-information was an EXTERNAL with only a direct-reference: no
// MMS Initiate-RequestPDU at all, although the comments here said it
// carried one. Without it an MMS server cannot establish the MMS
// association (PITF-077).

package wire

import (
	"bytes"
	"errors"
	"fmt"
)

// MMSApplicationContextOID is the BER-encoded OID for IEC
// 61850-8-1 (iso(1).standard(0).iso9506(9506).part(2).
// version1(3)). Encodes as 5 bytes: first two components
// pack into 0x28, then 9506 = 0xCA 0x22 (variable-length
// subid), then 0x02, 0x03.
//
// Used both:
//   - IN the AARQ we build (so the server sees who's calling).
//   - WHEN we parse the AARE the server returns (so we
//     confirm this is genuinely an IEC 61850-8-1 stack and
//     not a generic ACSE-speaking peer).
var MMSApplicationContextOID = []byte{0x28, 0xCA, 0x22, 0x02, 0x03}

// ErrNoMMSACSEResponse is returned by ParseACSEAssociateResponseMMS
// when the response doesn't contain the IEC 61850-8-1
// application-context OID. This is the negative-fingerprint
// signal: the server speaks COTP but isn't an MMS IED.
var ErrNoMMSACSEResponse = errors.New("mms: ACSE response did not echo IEC 61850-8-1 OID")

// ErrACSETooShort is returned when the response is shorter
// than the minimum framing we'd expect. Used as a guard
// against degenerate responses that would index out of range
// in the OID-search.
var ErrACSETooShort = errors.New("mms: ACSE response too short")

// BuildACSEAssociateRequestMMS returns the bytes of an ISO
// 8823 + 8327 + ACSE AARQ frame requesting the IEC 61850-8-1
// application context. The bytes are the COTP DT *payload*
// caller wraps in a COTP DT header (LI=02, type=0xF0,
// TPDU-nr=0x80) + TPKT before sending.
//
// Byte for byte the client AARQ of the w3h/icsmaster IEC 61850 MMS
// captures (TestBuildACSEAssociateRequestMMS_RealCapture). Layout:
//
//	0D B2                     Session CONNECT SPDU, len 178
//	  05 06 13 01 00 16 01 02   Connect Accept Item (options 0, version 2)
//	  14 02 00 02               Session User Requirements
//	  33 02 00 01 / 34 02 00 01 calling / called session selector 1
//	  C1 9C                     Session User Data, len 156
//	31 81 99                  Presentation CP-type SET, len 153
//	  A0 03 80 01 01            mode normal
//	  A2 81 91                  normal-mode-parameters, len 145
//	    81 04 00 00 00 01       calling presentation selector 1
//	    82 04 00 00 00 01       called presentation selector 1
//	    A4 23 ...               context list: 1 = ACSE, 3 = MMS (both BER)
//	    88 02 06 00             presentation-requirements
//	    61 5A 30 58 02 01 01 A0 53   user-data, context 1 (ACSE)
//	60 51                     ACSE AARQ, len 81
//	  80 02 07 80               protocol-version 1
//	  A1 07 06 05 28 CA 22 02 03 application-context-name 1.0.9506.2.3
//	  A2 06 06 04 2B CE 0F 02   called AP-title 1.3.9999.2
//	  A3 03 02 01 17            called AE-qualifier 23
//	  BE 35 28 33               user-information, EXTERNAL
//	    06 02 51 01 02 01 03    BER transfer syntax, presentation context 3
//	    A0 2A A8 28             MMS Initiate-RequestPDU:
//	      80 02 75 30             localDetailCalling 30000
//	      81 02 03 E8 82 02 03 E8 proposedMaxServOutstanding 1000 / 1000
//	      83 01 05                proposedDataStructureNestingLevel 5
//	      A4 17 80 01 01          initRequestDetail: version 1,
//	        81 03 05 FB 00        parameter CBB,
//	        82 0D 03 FF … FF 00   services supported
func BuildACSEAssociateRequestMMS() []byte {
	out := make([]byte, len(realClientAARQ))
	copy(out, realClientAARQ)
	return out
}

// realClientAARQ is the captured client AARQ (see
// BuildACSEAssociateRequestMMS).
var realClientAARQ = []byte{
	0x0D, 0xB2, 0x05, 0x06, 0x13, 0x01, 0x00, 0x16, 0x01, 0x02, 0x14, 0x02,
	0x00, 0x02, 0x33, 0x02, 0x00, 0x01, 0x34, 0x02, 0x00, 0x01, 0xC1, 0x9C,
	0x31, 0x81, 0x99, 0xA0, 0x03, 0x80, 0x01, 0x01, 0xA2, 0x81, 0x91, 0x81,
	0x04, 0x00, 0x00, 0x00, 0x01, 0x82, 0x04, 0x00, 0x00, 0x00, 0x01, 0xA4,
	0x23, 0x30, 0x0F, 0x02, 0x01, 0x01, 0x06, 0x04, 0x52, 0x01, 0x00, 0x01,
	0x30, 0x04, 0x06, 0x02, 0x51, 0x01, 0x30, 0x10, 0x02, 0x01, 0x03, 0x06,
	0x05, 0x28, 0xCA, 0x22, 0x02, 0x01, 0x30, 0x04, 0x06, 0x02, 0x51, 0x01,
	0x88, 0x02, 0x06, 0x00, 0x61, 0x5A, 0x30, 0x58, 0x02, 0x01, 0x01, 0xA0,
	0x53, 0x60, 0x51, 0x80, 0x02, 0x07, 0x80, 0xA1, 0x07, 0x06, 0x05, 0x28,
	0xCA, 0x22, 0x02, 0x03, 0xA2, 0x06, 0x06, 0x04, 0x2B, 0xCE, 0x0F, 0x02,
	0xA3, 0x03, 0x02, 0x01, 0x17, 0xBE, 0x35, 0x28, 0x33, 0x06, 0x02, 0x51,
	0x01, 0x02, 0x01, 0x03, 0xA0, 0x2A, 0xA8, 0x28, 0x80, 0x02, 0x75, 0x30,
	0x81, 0x02, 0x03, 0xE8, 0x82, 0x02, 0x03, 0xE8, 0x83, 0x01, 0x05, 0xA4,
	0x17, 0x80, 0x01, 0x01, 0x81, 0x03, 0x05, 0xFB, 0x00, 0x82, 0x0D, 0x03,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00,
}

// ParseACSEAssociateResponseMMS scans the COTP DT payload
// for the IEC 61850-8-1 application-context OID. Returns
// nil if found (positive MMS-IED fingerprint), an error
// otherwise.
//
// Why a byte-pattern scan rather than a full ASN.1 BER
// parse: the AARE structure varies across vendors (some
// add presentation-context echo lists, others don't), but
// every standards-compliant IEC 61850 IED echoes the
// application-context OID byte-for-byte in their AARE.
// A pattern scan is robust to layout variation and avoids
// pulling in a full ASN.1 dependency.
//
// The trade-off: false positive if the response just
// happens to contain the 5 bytes 0x28 0xCA 0x22 0x02 0x03
// somewhere. In practice this is vanishingly unlikely
// (the byte sequence is structured + uncommon) and the
// scan runs only after a successful COTP-CC, so the
// surrounding context already constrains it to OSI-style
// servers.
func ParseACSEAssociateResponseMMS(buf []byte) error {
	// COTP DT header is 3 bytes: LI (1) + type (1) +
	// TPDU-nr (1). The actual ACSE/Presentation/Session
	// payload follows. We don't parse those layers, we
	// just scan the whole buffer for the OID.
	if len(buf) < 3+len(MMSApplicationContextOID) {
		return fmt.Errorf("%w: %d bytes", ErrACSETooShort, len(buf))
	}
	if !bytes.Contains(buf, MMSApplicationContextOID) {
		return ErrNoMMSACSEResponse
	}
	return nil
}
