package wire

import (
	"encoding/binary"
)

// CallMethod is one parsed CallMethodRequest from a CallRequest
// MSG body. Both ObjectID and MethodID are rich NodeIDValues —
// operators can allowlist them in canonical-string form, same
// shape as v1.12 chunk 3 for WriteRequest NodeIds.
type CallMethod struct {
	ObjectID NodeIDValue
	MethodID NodeIDValue
}

// CallRequestAllMethods walks the MethodsToCall array of a
// CallRequest MSG body and returns every (ObjectID, MethodID)
// pair in document order.
//
// Returns (nil, false) when:
//   - The fixed request-prefix / RequestHeader doesn't parse.
//   - The MethodsToCall array prefix is null / negative.
//   - ANY CallMethodRequest fails to decode (unknown NodeId
//     encoding, unparseable InputArguments variant, truncated
//     buffer).
//
// Fail-closed semantics match WriteRequestAllNodes: the caller
// uses this for a multi-method allowlist check; any missed
// entry is worse than refusing the whole request.
//
// v1.12 chunk 6 complement of WriteRequestAllNodesRich.
func CallRequestAllMethods(msgBody []byte) (methods []CallMethod, ok bool) {
	body, arrLen, ok := walkWriteRequestArrayPrefix(msgBody)
	if !ok {
		return nil, false
	}
	off := 0
	out := make([]CallMethod, 0, arrLen)
	for i := int32(0); i < arrLen; i++ {
		cm, cmOff, cmOK := parseCallMethodRequest(body[off:])
		if !cmOK {
			return nil, false
		}
		out = append(out, cm)
		off += cmOff
	}
	return out, true
}

// parseCallMethodRequest parses one CallMethodRequest struct.
// Layout (OPC UA Part 4 §5.11.2):
//
//	ObjectId       NodeId
//	MethodId       NodeId
//	InputArguments Variant[]
//
// Returns (method, bytesConsumed, true) on success; (_, 0,
// false) on any parse error — caller fails closed.
func parseCallMethodRequest(b []byte) (CallMethod, int, bool) {
	off := 0
	obj, consumed, ok := parseNodeIDRich(b[off:])
	if !ok {
		return CallMethod{}, 0, false
	}
	off += consumed
	mth, consumed, ok := parseNodeIDRich(b[off:])
	if !ok {
		return CallMethod{}, 0, false
	}
	off += consumed
	argsConsumed, ok := skipVariantArray(b[off:])
	if !ok {
		return CallMethod{}, 0, false
	}
	off += argsConsumed
	return CallMethod{ObjectID: obj, MethodID: mth}, off, true
}

// skipVariantArray walks past a top-level Variant[] encoding:
// 4-byte Int32 length (-1 = null, no further bytes), then N
// Variants each walked via skipVariant. Returns bytes consumed
// or (0, false) on any parse error.
//
// Arbitrary cap 65536 arguments — same cap used inside
// skipVariant for array-element counts. Anything larger is
// either a bug or an attack.
func skipVariantArray(b []byte) (int, bool) {
	if len(b) < 4 {
		return 0, false
	}
	n := int32(binary.LittleEndian.Uint32(b[:4])) //nolint:gosec // G115 — -1 null sentinel intentional
	if n < 0 {
		return 4, true
	}
	const maxArrayLen = 1 << 16
	if n > maxArrayLen {
		return 0, false
	}
	off := 4
	for i := int32(0); i < n; i++ {
		consumed, ok := skipVariant(b[off:])
		if !ok {
			return 0, false
		}
		off += consumed
	}
	return off, true
}
