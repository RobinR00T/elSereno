package wire

import "encoding/binary"

// S7 Setup Communication + the shared S7-PDU building blocks for the
// active recon probes (COTP CR/CC already live in parse.go). Setup
// Communication is the mandatory second handshake after COTP: it
// negotiates the max concurrent jobs + PDU length, and every S7 request
// (Read Var, UserData/SZL, ...) requires it first.
//
// Field order/values follow a real captured S7-300 session (see
// setup_test.go, bytes from ITI/ICS-Security-Tools
// s7comm_reading_plc_status.pcap) + the Wireshark S7comm dissector.

// cotpDataHeader is the COTP DT (Data) header every S7 PDU rides on:
// LI=2, PDU type 0xF0 (Data), TPDU number 0x80 (end-of-TSDU marker).
var cotpDataHeader = []byte{0x02, COTPData, 0x80}

// setupParamFunc is the S7 parameter function byte for Setup
// Communication (same code as the Setup handshake FunctionCode).
const setupParamFunc = byte(FuncCommSetup)

// S7PDU returns the S7 protocol PDU (starting at the 0x32 protocol id)
// carried in a COTP Data payload (the bytes after the TPKT header).
// ok=false when the payload is not a COTP DT PDU, is truncated, or does
// not start with the S7 protocol id.
func S7PDU(cotpPayload []byte) ([]byte, bool) {
	t, ok := COTPType(cotpPayload)
	if !ok || t != COTPData {
		return nil, false
	}
	off := int(cotpPayload[0]) + 1 // COTP header is LI + the LI bytes that follow
	if off >= len(cotpPayload) {
		return nil, false
	}
	pdu := cotpPayload[off:]
	if len(pdu) < s7HeaderMin || pdu[0] != 0x32 {
		return nil, false
	}
	return pdu, true
}

// buildS7Header returns a 10-byte S7 header (protoID 0x32, ROSCTR,
// zero redundancy, pduRef, paramLen, dataLen). AckData responses carry 2
// extra error bytes; those are parsed, never built here.
func buildS7Header(rosctr byte, pduRef, paramLen, dataLen uint16) []byte {
	h := make([]byte, s7HeaderMin)
	h[0] = 0x32
	h[1] = rosctr
	binary.BigEndian.PutUint16(h[4:6], pduRef)
	binary.BigEndian.PutUint16(h[6:8], paramLen)
	binary.BigEndian.PutUint16(h[8:10], dataLen)
	return h
}

// BuildSetupCommunication returns the COTP+S7 payload (the bytes after
// the TPKT header, ready for WriteTPKT) for an S7 Setup Communication
// Job. It negotiates MaxAmQ 1/1 and a 480-byte PDU, matching a real
// S7-300 client. pduRef correlates the AckData response.
func BuildSetupCommunication(pduRef uint16) []byte {
	param := []byte{
		setupParamFunc, 0x00,
		0x00, 0x01, // MaxAmQ (calling)
		0x00, 0x01, // MaxAmQ (called)
		0x01, 0xE0, // requested PDU length = 480
	}
	out := make([]byte, 0, len(cotpDataHeader)+s7HeaderMin+len(param))
	out = append(out, cotpDataHeader...)
	out = append(out, buildS7Header(ROSCTRJob, pduRef, uint16(len(param)), 0)...) // #nosec G115 -- param length is a fixed 8
	out = append(out, param...)
	return out
}

// ParseSetupResponse extracts the negotiated PDU length from an S7 Setup
// Communication AckData PDU (starting at 0x32). ok=false when it is not
// a well-formed Setup AckData. The negotiated length is informational;
// the probe only needs to know the handshake succeeded.
func ParseSetupResponse(pdu []byte) (negotiatedPDULen uint16, ok bool) {
	// AckData header is s7HeaderMin + 2 error bytes = 12; param follows.
	const ackHeader = s7HeaderMin + 2
	if len(pdu) < ackHeader || pdu[0] != 0x32 || pdu[1] != ROSCTRAckData {
		return 0, false
	}
	param := pdu[ackHeader:]
	if len(param) < 8 || param[0] != setupParamFunc {
		return 0, false
	}
	return binary.BigEndian.Uint16(param[6:8]), true
}
