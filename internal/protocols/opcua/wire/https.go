package wire

// OPC UA HTTPS binary-binding helpers (Part 6 §7.4).
//
// The HTTPS binding carries a *bare* UA service message as the HTTP
// POST body: the message TypeId (a NodeId) sits at offset 0, followed
// by the RequestHeader and the service fields, with none of the
// opc.tcp MSG chunk framing (SecureChannelId + TokenId + SequenceNumber
// + RequestId) that precedes the TypeId on the TCP transport. See
// getendpoints.go for the canonical bare-body encoder
// (EncodeGetEndpointsRequest), which is exactly this shape.
//
// The service-classification + write/call parsers in this package
// (ServiceTypeID, WriteRequestAllNodesRich, CallRequestAllMethods) were
// written for the TCP MSG body and assume a 16-byte prefix ahead of the
// TypeId (headerPrefix in writerequest.go). Rather than fork those
// validated, fuzzed parsers for the HTTPS shape, the helpers below
// splice a 16-byte zero prefix in front of the bare body and delegate.
// The prefix bytes are never read for their value (ServiceTypeID reads
// the TypeId at offset 16; walkWriteRequestArrayPrefix starts the
// RequestHeader at offset 16+4), so zeros are safe filler.

// httpsMSGPrefix is the width of the opc.tcp MSG framing the bare
// HTTPS body lacks: SecureChannelId(4) + TokenId(4) + SequenceNumber(4)
// + RequestId(4). See ServiceTypeID's body-layout comment.
const httpsMSGPrefix = 16

// spliceTCPPrefix returns bare with a 16-byte zero prefix so the
// opc.tcp MSG parsers can consume an HTTPS-binding bare service body
// unchanged.
func spliceTCPPrefix(bare []byte) []byte {
	msg := make([]byte, httpsMSGPrefix+len(bare))
	copy(msg[httpsMSGPrefix:], bare)
	return msg
}

// ServiceTypeIDHTTPS decodes the service-request TypeId from a bare
// HTTPS-binding message body (TypeId at offset 0). Same (id, ok)
// contract as ServiceTypeID: ok=false when the TypeId is not a
// Two/FourByte numeric NodeId.
func ServiceTypeIDHTTPS(bare []byte) (uint16, bool) {
	return ServiceTypeID(spliceTCPPrefix(bare))
}

// WriteRequestAllNodesRichHTTPS walks every WriteValue's NodeId in a
// bare HTTPS WriteRequest body. Same fail-closed contract as
// WriteRequestAllNodesRich: (nil, false) on any parse failure, so the
// caller refuses the whole request.
func WriteRequestAllNodesRichHTTPS(bare []byte) ([]NodeIDValue, bool) {
	return WriteRequestAllNodesRich(spliceTCPPrefix(bare))
}

// CallRequestAllMethodsHTTPS walks every (ObjectID, MethodID) pair in a
// bare HTTPS CallRequest body. Same fail-closed contract as
// CallRequestAllMethods.
func CallRequestAllMethodsHTTPS(bare []byte) ([]CallMethod, bool) {
	return CallRequestAllMethods(spliceTCPPrefix(bare))
}

// TypeIDServiceFault is the DefaultBinary encoding NodeId of a
// ServiceFault message (namespace 0, Part 4 §7.5.2). A ServiceFault
// carries only a ResponseHeader; its ServiceResult conveys the error.
const TypeIDServiceFault uint16 = 397

// StatusBadUserAccessDenied is the OPC UA StatusCode returned when the
// gate refuses a write/call (Part 4 Annex A). The upper 16 bits are the
// severity + subcode; the lower 16 are informational.
const StatusBadUserAccessDenied uint32 = 0x80100000

// EncodeServiceFaultHTTPS builds a bare UA-Binary ServiceFault message
// for the HTTPS binding: the ServiceFault TypeId followed by a minimal
// ResponseHeader whose ServiceResult is `status`. The body is what a
// gated proxy returns (as the HTTP 200 response body, Content-Type
// application/octet-stream) so a real UA client decodes a parseable
// service error instead of a transport-level failure.
//
// ResponseHeader layout (Part 4 §7.29), mirroring
// EncodeGetEndpointsResponse:
//
//	Timestamp        DateTime (8 bytes) = 0
//	RequestHandle    u32              = 0
//	ServiceResult    StatusCode u32   = status
//	ServiceDiag      DiagnosticInfo   = 0x00 (empty)
//	StringTable      []String         = null array (-1)
//	AdditionalHeader ExtensionObject  = null NodeId + encoding 0x00
func EncodeServiceFaultHTTPS(status uint32) []byte {
	b := make([]byte, 0, 32)
	b = putFourByteNodeID(b, TypeIDServiceFault)
	b = putU32(b, 0)                // timestamp low 32 bits
	b = putU32(b, 0)                // timestamp high 32 bits (DateTime = 8 bytes)
	b = putU32(b, 0)                // requestHandle
	b = putU32(b, status)           // serviceResult
	b = append(b, 0x00)             // serviceDiagnostics: empty DiagnosticInfo
	b = putNullArray(b)             // stringTable: null array
	b = append(b, 0x00, 0x00, 0x00) // additionalHeader: null NodeId + encoding 0x00
	return b
}
