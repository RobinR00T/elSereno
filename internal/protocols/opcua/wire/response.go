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
