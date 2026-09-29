package wire

import "encoding/binary"

// StatusGood is the OPC UA "Good" StatusCode (Part 4 Annex A): the
// service call succeeded.
const StatusGood uint32 = 0x00000000

// ResponseServiceResult extracts the ResponseHeader.ServiceResult
// StatusCode from a UA MSG body (the bytes after the 8-byte UA-TCP
// header, the same input ServiceTypeID takes).
//
// Every UA service response begins, right after the message TypeId, with
// a ResponseHeader whose fixed prefix is Timestamp(UtcTime, 8) +
// RequestHandle(u32, 4) + ServiceResult(StatusCode, 4). A ServiceResult
// of StatusGood means the request succeeded; for an anonymous
// CreateSession / ActivateSession that is the confirmation that
// anonymous access actually works (not just that it is advertised).
//
// Returns ok=false when the body is too short or the TypeId is not a
// Two/FourByte numeric NodeId (service responses always are).
func ResponseServiceResult(msgBody []byte) (status uint32, ok bool) {
	if len(msgBody) < 17 {
		return 0, false
	}
	off := 16 // SecureChannelId(4)+TokenId(4)+SequenceNumber(4)+RequestId(4)
	switch NodeIDEncoding(msgBody[off]) {
	case NodeIDTwoByte:
		off += 2
	case NodeIDFourByte:
		off += 4
	default:
		return 0, false
	}
	// ResponseHeader: Timestamp(8) + RequestHandle(4) + ServiceResult(4).
	if off+8+4+4 > len(msgBody) {
		return 0, false
	}
	off += 8 + 4
	return binary.LittleEndian.Uint32(msgBody[off : off+4]), true
}

// ParseOpenSecureChannelResponse walks an OpenSecureChannelResponse OPN
// body (the bytes after the 8-byte UA-TCP header) and returns the
// SecurityToken's ChannelId + TokenId. Those two identify the secure
// channel on every subsequent MSG (they go in the symmetric security
// header), so a client must read them from the OPN response before it
// can send CreateSession.
//
// The OPN body layout (Part 6 §6.7.2): SecureChannelId(u32) +
// AsymmetricAlgorithmSecurityHeader(SecurityPolicyUri string +
// SenderCertificate bytestring + ReceiverCertificateThumbprint
// bytestring) + SequenceHeader(8) + TypeId(NodeId) + ResponseHeader +
// ServerProtocolVersion(u32) + SecurityToken(ChannelId u32 + TokenId u32
// + CreatedAt 8 + RevisedLifetime u32) + ServerNonce(bytestring).
//
// Reuses the bounds-checked cursor the GetEndpoints decoder uses, so the
// variable-length asymmetric header + ResponseHeader are walked, not
// assumed at fixed offsets. Fail-closed on truncation.
func ParseOpenSecureChannelResponse(body []byte) (channelID, tokenID uint32, ok bool) {
	c := &cur{b: body}
	_ = c.u32()    // SecureChannelId (channel-level; the token below is authoritative)
	_ = c.str()    // SecurityPolicyUri
	c.byteString() // SenderCertificate
	c.byteString() // ReceiverCertificateThumbprint
	c.skip(8)      // SequenceHeader: SequenceNumber + RequestId
	c.nodeID()     // message TypeId
	c.responseHeader()
	_ = c.u32()         // ServerProtocolVersion
	channelID = c.u32() // SecurityToken.ChannelId
	tokenID = c.u32()   // SecurityToken.TokenId
	if c.fail() {
		return 0, 0, false
	}
	return channelID, tokenID, true
}

// ParseCreateSessionAuthToken walks a CreateSessionResponse MSG body (the
// bytes after the 8-byte UA-TCP header) and returns the raw encoded
// AuthenticationToken NodeId. The client must echo that token in the
// RequestHeader of ActivateSession and every subsequent session request,
// so it is captured as raw bytes (any NodeId encoding: numeric, string,
// guid, opaque) rather than decoded.
//
// Body layout (Part 4 §5.6.2): 16-byte MSG prefix + TypeId + ResponseHeader
// + SessionId(NodeId) + AuthenticationToken(NodeId) + ... Fail-closed on
// truncation.
func ParseCreateSessionAuthToken(body []byte) (authToken []byte, ok bool) {
	c := &cur{b: body}
	c.skip(16) // SecureChannelId + TokenId + SequenceNumber + RequestId
	c.nodeID() // message TypeId
	c.responseHeader()
	c.nodeID() // SessionId
	start := c.off
	c.nodeID() // AuthenticationToken
	if c.fail() || start >= c.off || c.off > len(c.b) {
		return nil, false
	}
	out := make([]byte, c.off-start)
	copy(out, c.b[start:c.off])
	return out, true
}
