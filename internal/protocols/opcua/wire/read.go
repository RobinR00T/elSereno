package wire

import "encoding/binary"

// Read-service encode/decode for the OPC UA writeable-tag walk: given a
// NodeId, read the attributes that decide whether the anonymous user can
// write it (NodeClass + UserAccessLevel). This is the second half of the
// anonymous-exposure story (the first, `anonprobe.go`, proves a session
// opens; this proves what that session can then touch). Read-only recon:
// it reads attributes, it never issues a Write.
//
// VALIDATION NOTE: unlike the session-establishment wire (validated byte
// for byte against a real captured SecurityPolicy#None session), the real
// captures available for this project carry no Read service. So the Read
// encode/decode here is grounded in OPC-UA Part 4 (§5.10.2 Read, §7.24
// ReadValueId) + Part 6 (§5.2 binary encoding, DataValue/Variant) and
// validated by round-trip + spec-crafted DataValue fixtures (read_test.go),
// not by real bytes. The DataValue/Variant decoder is deliberately scoped
// to the integer scalar builtin types the two attributes use (NodeClass is
// an Int32 enum, UserAccessLevel a Byte); any other shape fails the parse
// closed rather than guessing.

// Attribute IDs (Part 6 §A.1). Only the two the walk reads are named.
const (
	// AttrNodeClass is the NodeClass attribute (id 2): tells a Variable
	// (2) from an Object/Method/etc, so the walk only flags real tags.
	AttrNodeClass uint32 = 2
	// AttrUserAccessLevel is the UserAccessLevel attribute (id 18): the
	// access the *current* (here: anonymous) user has, already reduced
	// from the role-independent AccessLevel (id 17). This is the field
	// that answers "can this stranger write it".
	AttrUserAccessLevel uint32 = 18
)

// NodeClassVariable is the NodeClass enum value for a Variable (Part 3
// §8.30): the only class that holds a writeable value.
const NodeClassVariable uint32 = 2

// AccessLevel bit masks (Part 3 §8.57). CurrentWrite is the bit that
// makes a node writeable now.
const (
	AccessLevelCurrentRead  byte = 0x01
	AccessLevelCurrentWrite byte = 0x02
)

// timestampsReturnNeither is TimestampsToReturn=Neither (Part 4 §7.40):
// attribute reads don't need source/server timestamps, so we ask for
// none and keep the response small.
const timestampsReturnNeither uint32 = 3

// builtin-type ids for the Variant scalars the attribute reads return
// (Part 6 Table 1). The walk only ever decodes integer scalars.
const (
	builtinBoolean byte = 1
	builtinSByte   byte = 2
	builtinByte    byte = 3
	builtinInt16   byte = 4
	builtinUInt16  byte = 5
	builtinInt32   byte = 6
	builtinUInt32  byte = 7
	builtinInt64   byte = 8
	builtinUInt64  byte = 9
)

// maxReadResults caps the DataValue array a ReadResponse may carry, so a
// hostile server can't drive a huge allocation from the array count.
const maxReadResults = 4096

// ReadTarget names one (NodeId, attribute) pair to read. NodeID is the
// raw encoded NodeId bytes (as produced by FourByteNodeID or captured
// from a BrowseResponse), so any NodeId encoding round-trips unchanged.
type ReadTarget struct {
	NodeID      []byte
	AttributeID uint32
}

// DataValueResult is one decoded ReadResponse result. For the walk only
// UintValue (the integer scalar) and Status matter; BuiltinType/HasValue
// let a caller sanity-check what came back.
type DataValueResult struct {
	Status      uint32 // DataValue.StatusCode when present (0 = Good), else 0
	HasValue    bool
	BuiltinType byte
	UintValue   uint64 // integer scalar value (Byte/Int16/Int32/...)
}

// putU16 appends a little-endian uint16.
func putU16(b []byte, v uint16) []byte {
	var tmp [2]byte
	binary.LittleEndian.PutUint16(tmp[:], v)
	return append(b, tmp[:]...)
}

// FourByteNodeID returns the raw wire bytes of a ns=0 FourByte NodeId
// (encoding 0x01 + ns u8 + id u16 LE). Well-known nodes the walk starts
// from (ObjectsFolder i=85, ...) are ns=0 numerics that fit this form.
func FourByteNodeID(id uint16) []byte {
	return putFourByteNodeID(nil, id)
}

// putNullQualifiedName appends a null QualifiedName (namespaceIndex 0 +
// null name String), used for a ReadValueId's dataEncoding.
func putNullQualifiedName(b []byte) []byte {
	b = putU16(b, 0)
	return putNullString(b)
}

// EncodeReadRequestTCP builds a ReadRequest MSG on an open, activated
// secure channel. authToken is the AuthenticationToken from
// CreateSessionResponse. Each target reads one attribute of one NodeId.
func EncodeReadRequestTCP(channelID, tokenID, seqNum, reqID uint32, authToken []byte, targets []ReadTarget) []byte {
	b := putSymmetricHeader(nil, channelID, tokenID, seqNum, reqID)
	b = putFourByteNodeID(b, TypeIDReadRequest)
	b = putRequestHeader(b, authToken)
	// ReadRequest body (Part 4 §5.10.2).
	b = putDouble(b, 0) // maxAge (ms); 0 = freshest
	b = putU32(b, timestampsReturnNeither)
	// nodesToRead array count.
	b = putI32(b, int32(len(targets))) // #nosec G115 -- caller batches a handful of attribute targets
	for _, t := range targets {
		b = append(b, t.NodeID...)   // ReadValueId.nodeId (raw NodeId)
		b = putU32(b, t.AttributeID) // ReadValueId.attributeId
		b = putNullString(b)         // ReadValueId.indexRange (null)
		b = putNullQualifiedName(b)  // ReadValueId.dataEncoding (null)
	}
	return wrap(MessageMessage, b)
}

// builtinScalarUint reads the fixed-width little-endian integer scalar of
// the given builtin type into a uint64. Non-integer / unknown builtin
// types fail the cursor closed (the walk only reads integer attributes).
func (c *cur) builtinScalarUint(builtin byte) uint64 {
	switch builtin {
	case builtinBoolean, builtinSByte, builtinByte:
		return uint64(c.u8())
	case builtinInt16, builtinUInt16:
		return uint64(c.u8()) | uint64(c.u8())<<8
	case builtinInt32, builtinUInt32:
		return uint64(c.u32())
	case builtinInt64, builtinUInt64:
		return uint64(c.u32()) | uint64(c.u32())<<32
	default:
		c.err = ErrShortResponse
		return 0
	}
}

// variantScalarInt reads a Variant (Part 6 §5.2.2.16) that must be a
// scalar integer builtin type, returning (hasValue, builtinType, value).
// A Null variant reports hasValue=false; an array or a non-integer
// builtin type fails the cursor closed.
func (c *cur) variantScalarInt() (has bool, builtin byte, value uint64) {
	encMask := c.u8()
	if c.fail() {
		return false, 0, 0
	}
	builtin = encMask & 0x3F
	if builtin == 0 {
		return false, 0, 0 // Null variant
	}
	if encMask&0x80 != 0 { // array flag: not expected for a scalar attribute
		c.err = ErrShortResponse
		return false, 0, 0
	}
	value = c.builtinScalarUint(builtin)
	return true, builtin, value
}

// dataValue reads a DataValue (Part 6 §5.2.2.17) and returns the decoded
// integer scalar (if any) plus the StatusCode.
func (c *cur) dataValue() DataValueResult {
	var dv DataValueResult
	mask := c.u8()
	if c.fail() {
		return dv
	}
	if mask&0x01 != 0 { // Value (Variant)
		dv.HasValue, dv.BuiltinType, dv.UintValue = c.variantScalarInt()
	}
	if mask&0x02 != 0 { // StatusCode
		dv.Status = c.u32()
	}
	if mask&0x04 != 0 { // SourceTimestamp
		c.skip(8)
	}
	if mask&0x08 != 0 { // ServerTimestamp
		c.skip(8)
	}
	if mask&0x10 != 0 { // SourcePicoseconds
		c.skip(2)
	}
	if mask&0x20 != 0 { // ServerPicoseconds
		c.skip(2)
	}
	return dv
}

// ParseReadResponse walks a ReadResponse MSG body (the bytes after the
// 8-byte UA-TCP header) and returns one DataValueResult per requested
// node, in request order. Fail-closed on truncation, an over-large
// result array, or a non-integer/array value (see the validation note).
func ParseReadResponse(msgBody []byte) ([]DataValueResult, bool) {
	c := &cur{b: msgBody}
	c.skip(16) // SecureChannelId + TokenId + SequenceNumber + RequestId
	c.nodeID() // message TypeId
	c.responseHeader()
	n := c.arrayLen() // results []DataValue
	if c.fail() || n > maxReadResults {
		return nil, false
	}
	out := make([]DataValueResult, 0, n)
	for i := int32(0); i < n && !c.fail(); i++ {
		out = append(out, c.dataValue())
	}
	if c.fail() {
		return nil, false
	}
	return out, true
}
