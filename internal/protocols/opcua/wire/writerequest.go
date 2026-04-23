package wire

import (
	"encoding/binary"
	"fmt"
)

// NodeID is the parsed form of an OPC-UA NodeId (Part 6 §5.2.2.9).
// Only the encodings the gate cares about are materialised:
// TwoByte + FourByte + Numeric produce concrete (ns, id) pairs.
// String / Guid / ByteString encodings return (0, 0, false) from
// parseNodeID — the caller treats them as "can't match; fall
// through to the next policy layer" rather than refusing the
// frame outright.
type NodeID struct {
	Namespace  uint16
	Identifier uint32
}

// WriteRequestFirstNode extracts the NodeId of the first
// WriteValue inside a WriteRequest MSG body. Returns:
//
//	id    — (namespace, identifier) of the first NodeId
//	nodes — the count of NodeId entries in NodesToWrite (0 on
//	        null array, otherwise the array length prefix)
//	ok    — true when the header + array length + first NodeId
//	        were all parseable; false when any layer didn't
//	        match an encoding we understand
//
// The caller is expected to fall back to the service-TypeID
// allowlist when ok==false. This conservative contract lets the
// gate work against OPC UA stacks that use rarer encodings
// (GUID NodeIds, String NodeIds) without refusing their traffic
// — those rarer cases just can't get the per-NodeId benefit.
//
// Input: the full MSG body (same bytes ServiceTypeID consumes).
// The caller has already confirmed TypeID == WriteRequest (673)
// before calling this.
//
// Layout consumed:
//
//	[0..3]   SecureChannelId
//	[4..7]   TokenId
//	[8..11]  SequenceNumber
//	[12..15] RequestId
//	[16..19] ExpandedNodeId prefix for WriteRequest TypeId
//	         (skipped — caller already validated)
//	[20..]   RequestHeader (see requestHeaderLen)
//	[...]    NodesToWrite array: u32 length + N × WriteValue
//	[...]    WriteValue: NodeId (variable) + AttributeId (u32) + …
func WriteRequestFirstNode(msgBody []byte) (id NodeID, nodes int, ok bool) {
	const headerPrefix = 16 // SCId + TokenId + SeqNo + ReqId
	const typeIDSize = 4    // FourByte NodeId: encoding(1) + ns(1) + id(u16)

	// Require at least the 16 bytes before the TypeId + 4 bytes
	// of TypeId + some RequestHeader + 4 bytes for array length
	// + 2 bytes for a minimum NodeId = ~55 bytes.
	if len(msgBody) < headerPrefix+typeIDSize+16 {
		return NodeID{}, 0, false
	}
	off := headerPrefix + typeIDSize

	// Skip the RequestHeader.
	consumed, ok := parseRequestHeader(msgBody[off:])
	if !ok {
		return NodeID{}, 0, false
	}
	off += consumed

	// NodesToWrite array length.
	if off+4 > len(msgBody) {
		return NodeID{}, 0, false
	}
	arrLen := int32(binary.LittleEndian.Uint32(msgBody[off : off+4])) //nolint:gosec // G115 — int32 cast is intentional; 0xFFFFFFFF = -1 is the UA "null array" sentinel we want to see
	off += 4
	if arrLen <= 0 {
		// Null or empty array — no NodeIds to gate against.
		return NodeID{}, 0, false
	}

	// First WriteValue starts here. Read its NodeId.
	n, consumed, ok := parseNodeID(msgBody[off:])
	if !ok {
		return NodeID{}, 0, false
	}
	_ = consumed // we only need the first NodeId
	return n, int(arrLen), true
}

// parseRequestHeader walks past a UA RequestHeader starting at
// the given buffer offset 0, returning the number of bytes
// consumed. Returns (_, false) on truncated buffer or an
// encoding we don't handle.
//
// RequestHeader layout (Part 4 §7.28):
//
//	AuthenticationToken: NodeId
//	Timestamp:           UtcTime (i64, 8 bytes)
//	RequestHandle:       u32 (4 bytes)
//	ReturnDiagnostics:   u32 (4 bytes)
//	AuditEntryId:        String (4-byte len + bytes; -1 = null)
//	TimeoutHint:         u32 (4 bytes)
//	AdditionalHeader:    ExtensionObject (NodeId + encoding + body)
func parseRequestHeader(b []byte) (int, bool) {
	off := 0
	// AuthenticationToken
	_, consumed, ok := parseNodeID(b[off:])
	if !ok {
		return 0, false
	}
	off += consumed
	// Timestamp(8) + RequestHandle(4) + ReturnDiagnostics(4)
	if off+8+4+4 > len(b) {
		return 0, false
	}
	off += 8 + 4 + 4
	// AuditEntryId String + TimeoutHint
	next, ok := skipAuditEntryAndTimeout(b, off)
	if !ok {
		return 0, false
	}
	off = next
	// AdditionalHeader ExtensionObject
	next, ok = skipAdditionalHeader(b, off)
	if !ok {
		return 0, false
	}
	return next, true
}

// skipAuditEntryAndTimeout walks past AuditEntryId (4-byte length
// prefix + bytes, or -1 null) + TimeoutHint (u32).
func skipAuditEntryAndTimeout(b []byte, off int) (int, bool) {
	if off+4 > len(b) {
		return 0, false
	}
	sLen := int32(binary.LittleEndian.Uint32(b[off : off+4])) //nolint:gosec // G115 — -1 null sentinel intentional
	off += 4
	if sLen > 0 {
		if off+int(sLen) > len(b) {
			return 0, false
		}
		off += int(sLen)
	}
	// TimeoutHint (u32)
	if off+4 > len(b) {
		return 0, false
	}
	off += 4
	return off, true
}

// skipAdditionalHeader walks past an ExtensionObject (NodeId +
// encoding + optional length-prefixed body).
func skipAdditionalHeader(b []byte, off int) (int, bool) {
	_, consumed, ok := parseNodeID(b[off:])
	if !ok {
		return 0, false
	}
	off += consumed
	if off+1 > len(b) {
		return 0, false
	}
	enc := b[off]
	off++
	switch enc {
	case 0:
		return off, true
	case 1, 2:
		if off+4 > len(b) {
			return 0, false
		}
		bLen := int32(binary.LittleEndian.Uint32(b[off : off+4])) //nolint:gosec // G115 — -1 null sentinel intentional
		off += 4
		if bLen > 0 {
			if off+int(bLen) > len(b) {
				return 0, false
			}
			off += int(bLen)
		}
		return off, true
	}
	return 0, false
}

// parseNodeID decodes one UA NodeId from the buffer starting at
// offset 0. Returns (node, consumed, ok). Supported encodings:
// TwoByte (2 bytes total), FourByte (4 bytes), Numeric (7 bytes).
// String / Guid / ByteString encodings are consumed structurally
// but the returned NodeID is a zero value with ok=false for those
// encodings — the caller treats that as "can't match".
func parseNodeID(b []byte) (NodeID, int, bool) {
	if len(b) < 1 {
		return NodeID{}, 0, false
	}
	enc := NodeIDEncoding(b[0])
	switch enc { //nolint:exhaustive // unknown encodings fall through to the default "cannot parse" path
	case NodeIDTwoByte:
		if len(b) < 2 {
			return NodeID{}, 0, false
		}
		return NodeID{Namespace: 0, Identifier: uint32(b[1])}, 2, true
	case NodeIDFourByte:
		if len(b) < 4 {
			return NodeID{}, 0, false
		}
		return NodeID{
			Namespace:  uint16(b[1]),
			Identifier: uint32(binary.LittleEndian.Uint16(b[2:4])),
		}, 4, true
	case NodeIDNumeric:
		if len(b) < 7 {
			return NodeID{}, 0, false
		}
		return NodeID{
			Namespace:  binary.LittleEndian.Uint16(b[1:3]),
			Identifier: binary.LittleEndian.Uint32(b[3:7]),
		}, 7, true
	case NodeIDString, NodeIDGuid, NodeIDByteString:
		consumed, ok := structuralSkip(b, enc)
		if !ok {
			return NodeID{}, 0, false
		}
		// We've consumed the NodeId successfully but can't
		// produce a (ns, id) pair for matching — signal "parse
		// ok, match not possible" by returning ok=false but the
		// caller distinguishes via consumed > 0.
		_ = consumed
		return NodeID{}, 0, false
	}
	return NodeID{}, 0, false
}

// structuralSkip returns the number of bytes a String / Guid /
// ByteString NodeId consumes, so the caller can walk past it
// when parsing a containing struct. Returns (_, false) on
// truncation. Intentionally unexported — v1.6 chunk 2 doesn't
// need it externally; a follow-up that supports matching on
// these encodings will promote it.
func structuralSkip(b []byte, enc NodeIDEncoding) (int, bool) {
	// All variable-length NodeId variants share the shape:
	//   [0]    encoding
	//   [1..2] namespace (u16)
	//   [3..]  identifier (encoding-specific)
	if len(b) < 3 {
		return 0, false
	}
	off := 3
	switch enc { //nolint:exhaustive // only called for String/Guid/ByteString
	case NodeIDString, NodeIDByteString:
		if off+4 > len(b) {
			return 0, false
		}
		sLen := int32(binary.LittleEndian.Uint32(b[off : off+4])) //nolint:gosec // G115 — -1 null sentinel intentional
		off += 4
		if sLen > 0 {
			if off+int(sLen) > len(b) {
				return 0, false
			}
			off += int(sLen)
		}
		return off, true
	case NodeIDGuid:
		if off+16 > len(b) {
			return 0, false
		}
		return off + 16, true
	}
	return 0, false
}

// String formats a NodeId in the canonical ns=N;i=M form.
func (n NodeID) String() string {
	return fmt.Sprintf("ns=%d;i=%d", n.Namespace, n.Identifier)
}
