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

// WriteRequestAllNodes walks the full NodesToWrite array and
// returns EVERY WriteValue's NodeId in document order.
//
// Returns (nil, false) when:
//   - The fixed request-prefix / RequestHeader doesn't parse.
//   - The NodesToWrite array prefix is null / negative.
//   - ANY WriteValue fails to decode (unknown NodeId encoding,
//     unparseable DataValue, truncated buffer, etc.).
//
// The fail-closed behaviour is intentional: the caller uses
// this for a multi-node allowlist check; if we can't verify
// every NodeId, the gate must refuse. Partial success is worse
// than refusal — it could let an attacker slip a malicious
// value in behind an unparseable one.
//
// v1.12 chunk 2 complement of WriteRequestFirstNode — that
// function still ships for v1.6-era callers that only need the
// first NodeId + don't want fail-closed semantics on unusual
// DataValue shapes.
func WriteRequestAllNodes(msgBody []byte) (ids []NodeID, ok bool) {
	const headerPrefix = 16
	const typeIDSize = 4

	if len(msgBody) < headerPrefix+typeIDSize+16 {
		return nil, false
	}
	off := headerPrefix + typeIDSize

	consumed, ok := parseRequestHeader(msgBody[off:])
	if !ok {
		return nil, false
	}
	off += consumed

	if off+4 > len(msgBody) {
		return nil, false
	}
	arrLen := int32(binary.LittleEndian.Uint32(msgBody[off : off+4])) //nolint:gosec // G115 — -1 null sentinel intentional
	off += 4
	if arrLen <= 0 {
		return nil, false
	}

	out := make([]NodeID, 0, arrLen)
	for i := int32(0); i < arrLen; i++ {
		n, wvOff, wvOK := parseWriteValue(msgBody[off:])
		if !wvOK {
			return nil, false
		}
		out = append(out, n)
		off += wvOff
	}
	return out, true
}

// parseWriteValue parses one WriteValue struct at the given
// buffer. Layout (OPC UA Part 4 §5.10.4):
//
//	NodeId     — variable (TwoByte / FourByte / Numeric handled)
//	AttributeId — UInt32 (4 bytes)
//	IndexRange  — String (4-byte len + bytes; -1 null)
//	Value       — DataValue
//
// Returns (nodeID, bytesConsumed, true) on success, (_, 0, false)
// on any parse error — the caller fails closed.
func parseWriteValue(b []byte) (NodeID, int, bool) {
	off := 0
	nid, consumed, ok := parseNodeID(b[off:])
	if !ok {
		// NodeId encoding we don't understand (String / Guid /
		// ByteString). The caller fails closed rather than try
		// to skip structurally — walking the WriteValue past
		// an unknown NodeId would produce nonsense offsets.
		return NodeID{}, 0, false
	}
	off += consumed
	// AttributeId (u32).
	if off+4 > len(b) {
		return NodeID{}, 0, false
	}
	off += 4
	// IndexRange (String). -1 length = null (0 extra bytes).
	if off+4 > len(b) {
		return NodeID{}, 0, false
	}
	sLen := int32(binary.LittleEndian.Uint32(b[off : off+4])) //nolint:gosec // G115 — -1 null sentinel intentional
	off += 4
	if sLen > 0 {
		if off+int(sLen) > len(b) {
			return NodeID{}, 0, false
		}
		off += int(sLen)
	}
	// DataValue.
	dvConsumed, ok := skipDataValue(b[off:])
	if !ok {
		return NodeID{}, 0, false
	}
	off += dvConsumed
	return nid, off, true
}

// skipDataValue walks past an OPC UA DataValue (Part 4
// §7.7). Returns the consumed byte count. On any parse error
// returns (0, false) — caller fails closed.
//
// DataValue layout:
//
//	Byte 0: EncodingMask
//	  bit 0: Value present (Variant)
//	  bit 1: StatusCode present (UInt32, 4 bytes)
//	  bit 2: SourceTimestamp present (Int64, 8 bytes)
//	  bit 3: ServerTimestamp present (Int64, 8 bytes)
//	  bit 4: SourcePicoseconds present (UInt16, 2 bytes)
//	  bit 5: ServerPicoseconds present (UInt16, 2 bytes)
//
// If Value present, a Variant follows. skipVariant handles the
// common scalar + array cases (Boolean through String + NodeId +
// ExtensionObject with null body). Complex nested types
// (Variant inside Variant, DataValue inside Variant,
// DiagnosticInfo) fall through to fail-closed refusal — write
// requests targeting ICS state rarely carry those shapes.
func skipDataValue(b []byte) (int, bool) {
	if len(b) < 1 {
		return 0, false
	}
	mask := b[0]
	off := 1
	if mask&0x01 != 0 { // Value present
		consumed, ok := skipVariant(b[off:])
		if !ok {
			return 0, false
		}
		off += consumed
	}
	if mask&0x02 != 0 { // StatusCode
		if off+4 > len(b) {
			return 0, false
		}
		off += 4
	}
	if mask&0x04 != 0 { // SourceTimestamp
		if off+8 > len(b) {
			return 0, false
		}
		off += 8
	}
	if mask&0x08 != 0 { // ServerTimestamp
		if off+8 > len(b) {
			return 0, false
		}
		off += 8
	}
	if mask&0x10 != 0 { // SourcePicoseconds
		if off+2 > len(b) {
			return 0, false
		}
		off += 2
	}
	if mask&0x20 != 0 { // ServerPicoseconds
		if off+2 > len(b) {
			return 0, false
		}
		off += 2
	}
	return off, true
}

// skipVariant walks past a scalar or 1-dim array Variant
// (Part 6 §5.2.2.16). Limited support — we handle the built-
// in types commonly targeted by operational writes (Boolean
// through Double, String, ByteString, NodeId). Dimensional
// arrays (multi-D) and recursive types (Variant, DataValue,
// DiagnosticInfo as BuiltInType) fall through to fail-closed.
func skipVariant(b []byte) (int, bool) {
	if len(b) < 1 {
		return 0, false
	}
	mask := b[0]
	builtIn := mask & 0x3F // bits 0..5
	isArray := mask&0x80 != 0
	hasDims := mask&0x40 != 0
	off := 1

	// Arbitrary cap: 65536 elements in a write array is plenty
	// for any operational target; anything larger is either a
	// bug or an attack.
	const maxArrayLen = 1 << 16

	count := 1
	if isArray {
		if off+4 > len(b) {
			return 0, false
		}
		n := int32(binary.LittleEndian.Uint32(b[off : off+4])) //nolint:gosec // G115 — -1 null sentinel intentional
		off += 4
		switch {
		case n < 0:
			// Null array. No further content for this builtin.
			count = 0
		case n > maxArrayLen:
			return 0, false
		default:
			count = int(n)
		}
	}

	for i := 0; i < count; i++ {
		consumed, ok := skipBuiltInType(b[off:], builtIn)
		if !ok {
			return 0, false
		}
		off += consumed
	}

	if hasDims {
		// Array dimensions: Int32 array. Rare — we stop trying
		// and fail closed.
		return 0, false
	}
	return off, true
}

// skipBuiltInType walks past one instance of the UA built-in
// type identified by builtIn (Part 6 §5.2.2.1 BuiltInType
// table). Limited support as documented above.
func skipBuiltInType(b []byte, builtIn byte) (int, bool) {
	switch builtIn {
	case 0: // Null
		return 0, true
	case 1, 2, 3: // Boolean, SByte, Byte — 1 byte
		return fixed(b, 1)
	case 4, 5: // Int16, UInt16 — 2 bytes
		return fixed(b, 2)
	case 6, 7, 10, 19: // Int32, UInt32, Float, StatusCode — 4 bytes
		return fixed(b, 4)
	case 8, 9, 11, 13: // Int64, UInt64, Double, DateTime — 8 bytes
		return fixed(b, 8)
	case 12, 15, 16: // String, ByteString, XmlElement — 4-byte len + bytes
		return skipLengthPrefixedBytes(b)
	case 14: // Guid — 16 bytes
		return fixed(b, 16)
	case 17: // NodeId
		_, c, ok := parseNodeID(b)
		if !ok {
			return 0, false
		}
		return c, true
	case 22: // ExtensionObject
		return skipExtensionObject(b)
	}
	// 18 ExpandedNodeId, 20 QualifiedName, 21 LocalizedText,
	// 23 DataValue, 24 Variant (recursive), 25 DiagnosticInfo
	// — fall through to fail-closed. The gate refuses rather
	// than try to walk an ambiguous encoding.
	return 0, false
}

// fixed returns the given length if the buffer is long enough.
func fixed(b []byte, n int) (int, bool) {
	if len(b) < n {
		return 0, false
	}
	return n, true
}

// skipLengthPrefixedBytes handles String / ByteString / Xml
// Element. 4-byte Int32 length; -1 = null (no further bytes).
func skipLengthPrefixedBytes(b []byte) (int, bool) {
	if len(b) < 4 {
		return 0, false
	}
	n := int32(binary.LittleEndian.Uint32(b[:4])) //nolint:gosec // G115 — -1 null sentinel intentional
	if n < 0 {
		return 4, true
	}
	if int64(4+n) > int64(len(b)) {
		return 0, false
	}
	return 4 + int(n), true
}

// skipExtensionObject handles BuiltInType 22 (Part 6 §5.2.2.15).
// Structure: TypeId (NodeId) + Encoding (1 byte) + optional body.
//
//	Encoding 0: no body (2 bytes consumed beyond the NodeId)
//	Encoding 1: ByteString body (length-prefixed)
//	Encoding 2: XmlElement body (length-prefixed)
func skipExtensionObject(b []byte) (int, bool) {
	_, nidLen, ok := parseNodeID(b)
	if !ok {
		return 0, false
	}
	off := nidLen
	if off+1 > len(b) {
		return 0, false
	}
	encoding := b[off]
	off++
	switch encoding {
	case 0:
		return off, true
	case 1, 2:
		extra, ok := skipLengthPrefixedBytes(b[off:])
		if !ok {
			return 0, false
		}
		return off + extra, true
	}
	return 0, false
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
