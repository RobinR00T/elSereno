//go:build offensive

// Package opcua implements the offensive write-gate proxy for
// OPC UA TCP (Part 6 §7.1 transport + Part 4 service framing).
//
// Architecture mirrors offensive/write/modbus (the ADR-040
// template): per-session Authorise on the SHA-256 of a sorted
// allowlist, per-frame filtering at wire-parse time. The UA
// specifics:
//
//   - Every client-to-server chunk is either HEL, OPN, MSG, or
//     CLO. HEL is the transport Hello (passes unchanged). OPN
//     opens a SecureChannel (passes unchanged; the gate is
//     higher-layer). CLO closes the channel (passes unchanged).
//     MSG carries service requests — that's where the gate acts.
//   - A MSG body begins with SecureChannelId + TokenId +
//     SequenceNumber + RequestId + ExpandedNodeId(TypeId). The
//     TypeId tells us WriteRequest (673) vs. CallRequest (704)
//     vs. ReadRequest / BrowseRequest / etc. Reads always pass;
//     writes + calls only pass when the service is in the
//     allowlist.
//   - Refusal path is a UA-native ServiceFault: same MSG chunk
//     framing, service TypeId 397 (ServiceFault), status
//     0x80100000 (BadUserAccessDenied). Real clients get a
//     parseable UA error rather than a TCP RST.
//
// Out of scope for v1.2 chunk 2: per-NodeId allowlisting (the
// TypeId alone is the gate). Full WriteValue / CallMethodRequest
// parsing to scope writes to specific nodes ships with v1.3
// alongside the UA binary-encoding parser.
package opcua

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"

	"local/elsereno/internal/protocols/opcua/wire"
	"local/elsereno/offensive/confirm"
	"local/elsereno/offensive/replay"
)

// AllowedService names one UA service the operator has
// authorised for the session. A literal BrowseRequest or
// ReadRequest entry is redundant — reads always pass — so the
// useful values here are TypeIDWriteRequest + TypeIDCallRequest.
// An empty allowlist is a "no writes" session, equivalent to
// the default deny-all proxy.
type AllowedService struct {
	// TypeID is a UA service request identifier (see
	// internal/protocols/opcua/wire TypeID*).
	TypeID uint16
}

// AllowedNodeID scopes a WriteRequest to a specific numeric
// target NodeId (ns + u32 identifier). When the handler's
// AllowedNodeIDs field is non-nil, a WriteRequest MSG is
// forwarded ONLY when:
//
//   - its service TypeID is in the Allowed list (the v1.2
//     service-level gate), AND
//   - EVERY WriteValue's NodeId matches either an AllowedNodeID
//     (numeric v1.6 path) OR a canonical-string entry in
//     AllowedCanonicalNodeIDs (String / Guid / ByteString v1.12
//     path).
//
// The per-node gate is opt-in: empty AllowedNodeIDs AND empty
// AllowedCanonicalNodeIDs falls back to v1.2 behaviour (service-
// TypeID allowlist only).
//
// v1.6 shipped numeric-only; v1.12 chunk 3 adds the String /
// Guid / ByteString encodings via AllowedCanonicalNodeIDs. A
// WriteRequest that mixes numeric + non-numeric NodeIDs still
// passes as long as every entry is in its respective list.
type AllowedNodeID struct {
	Namespace  uint16
	Identifier uint32
}

// AllowedCallMethod scopes a UA CallRequest to a specific
// (ObjectID, MethodID) pair. When the handler's
// AllowedCallMethods field is non-empty, a CallRequest MSG is
// forwarded ONLY when:
//
//   - its service TypeID is in Allowed (the v1.2 service-level
//     gate), AND
//   - EVERY CallMethodRequest's (ObjectID, MethodID) pair
//     matches one of these entries.
//
// Both fields are NodeIds in the canonical string form used by
// AllowedCanonicalNodeID (see below): `ns=N;i=M` for numeric,
// `ns=N;s=STR` for string, `ns=N;g=HEX` for GUID,
// `ns=N;b=HEX` for ByteString. Exact match only — method calls
// are capability-grants, so prefix / range matching is
// deliberately not supported.
//
// v1.12 chunk 6: the complement to v1.12 chunk 3 for
// WriteRequest NodeIds. Where chunk 3 gates `write this
// variable`, this gates `call this method on this object` —
// the other mutating-service surface area.
//
// Empty list disables the per-method gate (CallRequests still
// allowed service-wide if 704 is in Allowed).
type AllowedCallMethod struct {
	// ObjectID is the canonical-string NodeId of the Object
	// node the method is being called on (e.g. the Folder or
	// Object containing the method). Exact match.
	ObjectID string
	// MethodID is the canonical-string NodeId of the Method
	// node itself. Exact match.
	MethodID string
}

// AllowedCanonicalNodeID is a UA NodeId in the canonical string
// form the operator types on the CLI / YAML: `ns=N;i=M`,
// `ns=N;s=STR`, `ns=N;g=HEXGUID`, `ns=N;b=HEXBYTES`. The v1.12
// chunk 3 addition: covers encodings the numeric AllowedNodeID
// can't represent (String / Guid / ByteString).
//
// Canonical strings from the wire (produced by
// wire.NodeIDValue.Canonical()) use uppercase hex for GUIDs and
// ByteStrings; the hash and gate-check treat entries as raw
// strings, so operator-supplied values must match the wire form
// exactly — lowercase hex wouldn't match. The CLI flag parser
// normalises to uppercase to close that gap.
type AllowedCanonicalNodeID string

// AllowlistHash returns the deterministic SHA-256 of the
// service-TypeID allowlist. Entries are sorted numerically
// before hashing so the operator's dry-run token is stable
// regardless of input order.
//
// v1.2 callers (service-TypeID only) keep the same hash they've
// always seen. Operators who opt into per-NodeId gating use
// AllowlistHashWithNodeIDs instead, which mixes both dimensions
// into the hash.
func AllowlistHash(target string, allowed []AllowedService) [32]byte {
	sorted := append([]AllowedService(nil), allowed...)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].TypeID < sorted[j].TypeID
	})
	h := sha256.New()
	_, _ = h.Write([]byte(target))
	_, _ = h.Write([]byte{0x00})
	var buf [2]byte
	for _, a := range sorted {
		binary.BigEndian.PutUint16(buf[:], a.TypeID)
		_, _ = h.Write(buf[:])
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// AllowlistHashWithNodeIDs is the v1.6 per-NodeId hash that
// incorporates both the service-TypeID allowlist AND a sorted
// per-NodeId allowlist. When nodeIDs is nil or empty, the hash
// is identical to AllowlistHash(target, services) so operators
// who don't opt into per-node gating keep their existing
// tokens.
//
// Hash layout on the wire:
//
//	target || 0x00 || TypeID(BE16) × sorted_services
//	                    [|| 0xFF || namespace(BE16) || id(BE32) × sorted_nodeIDs]
//
// The 0xFF separator between the services block and the NodeIDs
// block is chosen so it can never collide with a TypeID (TypeIDs
// are little-endian 16-bit values but the hash writes big-
// endian; a BE TypeID byte of 0xFF would require TypeID ≥ 0xFF00,
// which is outside the Part 4 Table 17 allocation).
func AllowlistHashWithNodeIDs(target string, services []AllowedService, nodeIDs []AllowedNodeID) [32]byte {
	// v1.2 compatibility: no NodeIDs → v1.2 hash.
	if len(nodeIDs) == 0 {
		return AllowlistHash(target, services)
	}
	sortedSvc := append([]AllowedService(nil), services...)
	sort.Slice(sortedSvc, func(i, j int) bool { return sortedSvc[i].TypeID < sortedSvc[j].TypeID })
	sortedNodes := append([]AllowedNodeID(nil), nodeIDs...)
	sort.Slice(sortedNodes, func(i, j int) bool {
		if sortedNodes[i].Namespace != sortedNodes[j].Namespace {
			return sortedNodes[i].Namespace < sortedNodes[j].Namespace
		}
		return sortedNodes[i].Identifier < sortedNodes[j].Identifier
	})

	h := sha256.New()
	_, _ = h.Write([]byte(target))
	_, _ = h.Write([]byte{0x00})
	var u16 [2]byte
	for _, a := range sortedSvc {
		binary.BigEndian.PutUint16(u16[:], a.TypeID)
		_, _ = h.Write(u16[:])
	}
	_, _ = h.Write([]byte{0xFF}) // separator (cannot collide with TypeID high byte)
	var u32 [4]byte
	for _, n := range sortedNodes {
		binary.BigEndian.PutUint16(u16[:], n.Namespace)
		_, _ = h.Write(u16[:])
		binary.BigEndian.PutUint32(u32[:], n.Identifier)
		_, _ = h.Write(u32[:])
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// AllowlistHashWithRichNodeIDs is the v1.12 chunk-3 extension
// that also folds String / Guid / ByteString NodeIDs (in their
// canonical string form) into the PayloadHash. The hash ladder:
//
//   - canonicalNodeIDs empty → degrades to AllowlistHashWithNodeIDs.
//   - nodeIDs AND canonicalNodeIDs empty → degrades further to
//     AllowlistHash (v1.2 hash).
//
// This preserves tokens minted by v1.2 / v1.6 / v1.9 operators
// who never opt into per-NodeId gating. Operators who add
// canonical entries get a new hash (new token required).
//
// Hash layout on the wire:
//
//	AllowlistHashWithNodeIDs output
//	  [|| 0xFD || canonical(len BE16 + bytes) × sorted_canonicalNodeIDs]
//
// 0xFD separator is chosen after 0xFF (NodeID block separator
// from v1.6) so the v1.6 block always terminates before the
// v1.12 block begins. The per-entry `len BE16 + bytes`
// length-prefix prevents cross-entry bleed ("ns=1;s=A" +
// "B" hashing the same as "ns=1;s=AB").
func AllowlistHashWithRichNodeIDs(target string, services []AllowedService, nodeIDs []AllowedNodeID, canonicalNodeIDs []AllowedCanonicalNodeID) [32]byte {
	// v1.6 / v1.2 compatibility: no canonical entries → v1.6 hash.
	if len(canonicalNodeIDs) == 0 {
		return AllowlistHashWithNodeIDs(target, services, nodeIDs)
	}
	// Recompute v1.6 hash body, then append the 0xFD block.
	// Can't just feed the v1.6 output through sha256 again without
	// losing the target/service/nodeIDs detail, so we re-walk.
	sortedSvc := append([]AllowedService(nil), services...)
	sort.Slice(sortedSvc, func(i, j int) bool { return sortedSvc[i].TypeID < sortedSvc[j].TypeID })
	sortedNodes := append([]AllowedNodeID(nil), nodeIDs...)
	sort.Slice(sortedNodes, func(i, j int) bool {
		if sortedNodes[i].Namespace != sortedNodes[j].Namespace {
			return sortedNodes[i].Namespace < sortedNodes[j].Namespace
		}
		return sortedNodes[i].Identifier < sortedNodes[j].Identifier
	})
	sortedCanon := append([]AllowedCanonicalNodeID(nil), canonicalNodeIDs...)
	sort.Slice(sortedCanon, func(i, j int) bool { return sortedCanon[i] < sortedCanon[j] })

	h := sha256.New()
	_, _ = h.Write([]byte(target))
	_, _ = h.Write([]byte{0x00})
	var u16 [2]byte
	for _, a := range sortedSvc {
		binary.BigEndian.PutUint16(u16[:], a.TypeID)
		_, _ = h.Write(u16[:])
	}
	// v1.6 numeric NodeID block — only emitted when nodeIDs has
	// entries; otherwise skip the 0xFF separator so the canonical
	// block isn't preceded by a redundant empty block.
	if len(sortedNodes) > 0 {
		_, _ = h.Write([]byte{0xFF})
		var u32 [4]byte
		for _, n := range sortedNodes {
			binary.BigEndian.PutUint16(u16[:], n.Namespace)
			_, _ = h.Write(u16[:])
			binary.BigEndian.PutUint32(u32[:], n.Identifier)
			_, _ = h.Write(u32[:])
		}
	}
	// v1.12 canonical NodeID block.
	_, _ = h.Write([]byte{0xFD})
	for _, c := range sortedCanon {
		s := string(c)
		// Length-prefix bounded to uint16 — any single canonical
		// NodeID longer than 65535 bytes is truncated at hash
		// time. In practice UA NodeID strings are well under 1 KB.
		n := len(s)
		if n > 0xFFFF {
			n = 0xFFFF
		}
		binary.BigEndian.PutUint16(u16[:], uint16(n)) // #nosec G115 -- explicit cap above
		_, _ = h.Write(u16[:])
		_, _ = h.Write([]byte(s)[:n])
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// SessionMutation builds the confirm.Mutation that authorises
// the proxy session for target + service-TypeID allowlist. v1.2
// compatibility.
func SessionMutation(target string, allowed []AllowedService) confirm.Mutation {
	return confirm.Mutation{
		Category:    confirm.CategoryWrite,
		Protocol:    "opcua",
		Operation:   "proxy_session",
		Target:      target,
		PayloadHash: AllowlistHash(target, allowed),
	}
}

// SessionMutationWithNodeIDs is the v1.6 Mutation that mixes
// both service-TypeID + per-NodeId into the PayloadHash. When
// nodeIDs is nil/empty it degrades to SessionMutation.
func SessionMutationWithNodeIDs(target string, services []AllowedService, nodeIDs []AllowedNodeID) confirm.Mutation {
	return confirm.Mutation{
		Category:    confirm.CategoryWrite,
		Protocol:    "opcua",
		Operation:   "proxy_session",
		Target:      target,
		PayloadHash: AllowlistHashWithNodeIDs(target, services, nodeIDs),
	}
}

// SessionMutationWithRichNodeIDs is the v1.12 chunk-3 Mutation
// that mixes service-TypeID + numeric NodeID + canonical-string
// NodeID into the PayloadHash. When canonicalNodeIDs is
// nil/empty it degrades to SessionMutationWithNodeIDs.
func SessionMutationWithRichNodeIDs(target string, services []AllowedService, nodeIDs []AllowedNodeID, canonicalNodeIDs []AllowedCanonicalNodeID) confirm.Mutation {
	return confirm.Mutation{
		Category:    confirm.CategoryWrite,
		Protocol:    "opcua",
		Operation:   "proxy_session",
		Target:      target,
		PayloadHash: AllowlistHashWithRichNodeIDs(target, services, nodeIDs, canonicalNodeIDs),
	}
}

// AllowlistHashWithCallMethods is the v1.12 chunk-6 hash that
// adds a per-CallMethod (Object, Method) block on top of all
// previous hash layers. Ladder:
//
//   - callMethods empty → equals AllowlistHashWithRichNodeIDs
//     (v1.12 chunk 3).
//   - callMethods + canonicalNodeIDs both empty → equals
//     AllowlistHashWithNodeIDs (v1.6).
//   - canonicalNodeIDs + numeric + callMethods all empty →
//     equals AllowlistHash (v1.2).
//
// Hash layout (when callMethods is non-empty):
//
//	AllowlistHashWithRichNodeIDs output
//	  || 0xFC || (len(object) BE16 + object || len(method) BE16 + method) × sorted_callMethods
//
// The 0xFC separator is chosen below 0xFD / 0xFE / 0xFF used by
// previous blocks. Each entry is length-prefixed per field so
// an attacker can't craft two lists whose concatenation
// collides.
func AllowlistHashWithCallMethods(target string, services []AllowedService, nodeIDs []AllowedNodeID, canonicalNodeIDs []AllowedCanonicalNodeID, callMethods []AllowedCallMethod) [32]byte {
	if len(callMethods) == 0 {
		return AllowlistHashWithRichNodeIDs(target, services, nodeIDs, canonicalNodeIDs)
	}
	// Reuse the rich-node-ID hash body by recomputing inline; we
	// can't append to an already-finalised sha256 output.
	sortedSvc := append([]AllowedService(nil), services...)
	sort.Slice(sortedSvc, func(i, j int) bool { return sortedSvc[i].TypeID < sortedSvc[j].TypeID })
	sortedNodes := append([]AllowedNodeID(nil), nodeIDs...)
	sort.Slice(sortedNodes, func(i, j int) bool {
		if sortedNodes[i].Namespace != sortedNodes[j].Namespace {
			return sortedNodes[i].Namespace < sortedNodes[j].Namespace
		}
		return sortedNodes[i].Identifier < sortedNodes[j].Identifier
	})
	sortedCanon := append([]AllowedCanonicalNodeID(nil), canonicalNodeIDs...)
	sort.Slice(sortedCanon, func(i, j int) bool { return sortedCanon[i] < sortedCanon[j] })
	sortedCalls := append([]AllowedCallMethod(nil), callMethods...)
	sort.Slice(sortedCalls, func(i, j int) bool {
		if sortedCalls[i].ObjectID != sortedCalls[j].ObjectID {
			return sortedCalls[i].ObjectID < sortedCalls[j].ObjectID
		}
		return sortedCalls[i].MethodID < sortedCalls[j].MethodID
	})

	h := sha256.New()
	_, _ = h.Write([]byte(target))
	_, _ = h.Write([]byte{0x00})
	var u16 [2]byte
	for _, a := range sortedSvc {
		binary.BigEndian.PutUint16(u16[:], a.TypeID)
		_, _ = h.Write(u16[:])
	}
	if len(sortedNodes) > 0 {
		_, _ = h.Write([]byte{0xFF})
		var u32 [4]byte
		for _, n := range sortedNodes {
			binary.BigEndian.PutUint16(u16[:], n.Namespace)
			_, _ = h.Write(u16[:])
			binary.BigEndian.PutUint32(u32[:], n.Identifier)
			_, _ = h.Write(u32[:])
		}
	}
	if len(sortedCanon) > 0 {
		_, _ = h.Write([]byte{0xFD})
		for _, c := range sortedCanon {
			writeLengthPrefixedString(h, string(c))
		}
	}
	_, _ = h.Write([]byte{0xFC})
	for _, cm := range sortedCalls {
		writeLengthPrefixedString(h, cm.ObjectID)
		writeLengthPrefixedString(h, cm.MethodID)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// writeLengthPrefixedString writes s as uint16-len + bytes to
// the hash. Single caller today (AllowlistHashWithCallMethods)
// but future ladder additions will reuse it.
func writeLengthPrefixedString(h interface {
	Write([]byte) (int, error)
}, s string) {
	n := len(s)
	if n > 0xFFFF {
		n = 0xFFFF
	}
	var u16 [2]byte
	binary.BigEndian.PutUint16(u16[:], uint16(n)) // #nosec G115 -- explicit cap above
	_, _ = h.Write(u16[:])
	_, _ = h.Write([]byte(s)[:n])
}

// SessionMutationWithCallMethods is the v1.12 chunk-6 Mutation
// mixing every per-session granularity (service + numeric /
// canonical NodeID + per-CallMethod) into the PayloadHash.
// When callMethods is nil/empty it degrades to
// SessionMutationWithRichNodeIDs.
func SessionMutationWithCallMethods(target string, services []AllowedService, nodeIDs []AllowedNodeID, canonicalNodeIDs []AllowedCanonicalNodeID, callMethods []AllowedCallMethod) confirm.Mutation {
	return confirm.Mutation{
		Category:    confirm.CategoryWrite,
		Protocol:    "opcua",
		Operation:   "proxy_session",
		Target:      target,
		PayloadHash: AllowlistHashWithCallMethods(target, services, nodeIDs, canonicalNodeIDs, callMethods),
	}
}

// AllowlistHashWithGeneration is the v1.17 chunk-3 hash that
// adds the token-generation cookie. generation == 0 → equals
// AllowlistHashWithCallMethods. Mirrors the BACnet/CWMP/SIP/
// Modbus/IAX2/pbxhttp design.
//
// Hash layout (when generation != 0): same lower-layer bytes
// as chunk-6 (services + optional 0xFF nodeIDs + optional 0xFD
// canonical + optional 0xFC callMethods) followed by:
//
//	|| 0xFB || u32 generation (big-endian)
//
// Separator 0xFB is below 0xFC (callMethods), 0xFD (canonical
// NodeIDs), and 0xFF (numeric NodeIDs). 5-byte block.
func AllowlistHashWithGeneration(target string, services []AllowedService, nodeIDs []AllowedNodeID, canonicalNodeIDs []AllowedCanonicalNodeID, callMethods []AllowedCallMethod, generation uint32) [32]byte {
	if generation == 0 {
		return AllowlistHashWithCallMethods(target, services, nodeIDs, canonicalNodeIDs, callMethods)
	}
	sortedSvc, sortedNodes, sortedCanon, sortedCalls := canonOPCUAAllowlist(services, nodeIDs, canonicalNodeIDs, callMethods)

	h := sha256.New()
	_, _ = h.Write([]byte(target))
	_, _ = h.Write([]byte{0x00})
	var u16 [2]byte
	for _, a := range sortedSvc {
		binary.BigEndian.PutUint16(u16[:], a.TypeID)
		_, _ = h.Write(u16[:])
	}
	if len(sortedNodes) > 0 {
		_, _ = h.Write([]byte{0xFF})
		var u32 [4]byte
		for _, n := range sortedNodes {
			binary.BigEndian.PutUint16(u16[:], n.Namespace)
			_, _ = h.Write(u16[:])
			binary.BigEndian.PutUint32(u32[:], n.Identifier)
			_, _ = h.Write(u32[:])
		}
	}
	if len(sortedCanon) > 0 {
		_, _ = h.Write([]byte{0xFD})
		for _, c := range sortedCanon {
			writeLengthPrefixedString(h, string(c))
		}
	}
	if len(sortedCalls) > 0 {
		_, _ = h.Write([]byte{0xFC})
		for _, cm := range sortedCalls {
			writeLengthPrefixedString(h, cm.ObjectID)
			writeLengthPrefixedString(h, cm.MethodID)
		}
	}
	var u32 [4]byte
	binary.BigEndian.PutUint32(u32[:], generation)
	_, _ = h.Write([]byte{0xFB})
	_, _ = h.Write(u32[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// canonOPCUAAllowlist canonicalises + sorts the four allowlist
// dimensions for hash inclusion. Extracted from
// AllowlistHashWithGeneration to keep that function under
// funlen.
func canonOPCUAAllowlist(services []AllowedService, nodeIDs []AllowedNodeID, canonicalNodeIDs []AllowedCanonicalNodeID, callMethods []AllowedCallMethod) ([]AllowedService, []AllowedNodeID, []AllowedCanonicalNodeID, []AllowedCallMethod) {
	sortedSvc := append([]AllowedService(nil), services...)
	sort.Slice(sortedSvc, func(i, j int) bool { return sortedSvc[i].TypeID < sortedSvc[j].TypeID })
	sortedNodes := append([]AllowedNodeID(nil), nodeIDs...)
	sort.Slice(sortedNodes, func(i, j int) bool {
		if sortedNodes[i].Namespace != sortedNodes[j].Namespace {
			return sortedNodes[i].Namespace < sortedNodes[j].Namespace
		}
		return sortedNodes[i].Identifier < sortedNodes[j].Identifier
	})
	sortedCanon := append([]AllowedCanonicalNodeID(nil), canonicalNodeIDs...)
	sort.Slice(sortedCanon, func(i, j int) bool { return sortedCanon[i] < sortedCanon[j] })
	sortedCalls := append([]AllowedCallMethod(nil), callMethods...)
	sort.Slice(sortedCalls, func(i, j int) bool {
		if sortedCalls[i].ObjectID != sortedCalls[j].ObjectID {
			return sortedCalls[i].ObjectID < sortedCalls[j].ObjectID
		}
		return sortedCalls[i].MethodID < sortedCalls[j].MethodID
	})
	return sortedSvc, sortedNodes, sortedCanon, sortedCalls
}

// SessionMutationWithGeneration is the v1.17 chunk-3 Mutation,
// the new top of the OPC UA hash ladder.
func SessionMutationWithGeneration(target string, services []AllowedService, nodeIDs []AllowedNodeID, canonicalNodeIDs []AllowedCanonicalNodeID, callMethods []AllowedCallMethod, generation uint32) confirm.Mutation {
	return confirm.Mutation{
		Category:    confirm.CategoryWrite,
		Protocol:    "opcua",
		Operation:   "proxy_session",
		Target:      target,
		PayloadHash: AllowlistHashWithGeneration(target, services, nodeIDs, canonicalNodeIDs, callMethods, generation),
	}
}

// WriteGatedHandler is the offensive replacement for the default
// UA deny-all proxy. Construction requires triple-confirm
// authorised session context (Deriver, Auditor, and the
// session-level Confirm struct). The handler does NOT
// re-authorise per frame — it parses the UA-TCP framing and
// allows (a) HEL/OPN/CLO always, (b) MSG with TypeId in the
// allowlist OR any non-mutating service TypeId.
type WriteGatedHandler struct {
	// Target is the upstream host:port. Must match
	// confirm.Mutation.Target used to mint the session token.
	Target string
	// Allowed is the list of service TypeIds the operator
	// authorised at session open. Empty list forbids every
	// mutating service (equivalent to the default deny-all
	// handler for writes; reads still pass).
	Allowed []AllowedService
	// AllowedNodeIDs is the optional v1.6 per-node allowlist for
	// numeric-encoded NodeIDs (TwoByte / FourByte / Numeric). See
	// AllowedNodeID for the combined v1.6 + v1.12 gate semantics.
	AllowedNodeIDs []AllowedNodeID
	// AllowedCanonicalNodeIDs is the v1.12 chunk-3 per-node
	// allowlist for String / Guid / ByteString encodings (and
	// optionally numeric entries expressed in canonical form).
	// When either AllowedNodeIDs or this field has entries, the
	// gate walks EVERY WriteValue and admits a frame only when
	// every NodeId matches its respective list.
	AllowedCanonicalNodeIDs []AllowedCanonicalNodeID
	// AllowedCallMethods is the v1.12 chunk-6 per-CallMethod
	// allowlist. When non-empty, a CallRequest MSG is forwarded
	// only when EVERY CallMethodRequest's (ObjectID, MethodID)
	// pair matches one of these entries. Empty disables the
	// per-method gate but leaves CallRequest allowed if 704 is
	// in the service Allowed list (v1.2 behaviour).
	AllowedCallMethods []AllowedCallMethod
	// TokenGeneration is the v1.17 chunk-3 cookie. Default 0
	// preserves the v1.12-chunk-6 hash for backwards-compat.
	TokenGeneration uint32
	// Deriver + Auditor drive the session-open Authorize call.
	Deriver confirm.KeyDeriver
	Auditor confirm.Auditor
	// SessionConfirm is the Confirm struct the CLI populates
	// from --accept-writes / --confirm-target / --confirm-token.
	SessionConfirm confirm.Confirm

	// Recorder is the optional v1.30-chunk-1 hook for capturing
	// the proxy session to an NDJSON file. When non-nil, Handle
	// wraps both client + upstream io.ReadWriter through the
	// recorder so every chunk that crosses the gate is
	// timestamped + direction-tagged + persisted. Wrapping
	// happens BEFORE the OPC UA chunk parser reads, so HEL /
	// OPN / MSG (with all the v1.6/v1.12 NodeId + CallMethod
	// gating) / CLO routing is captured intact. Nil disables
	// recording — the gate behaves exactly as it did pre-v1.30.
	Recorder *replay.Recorder

	// authorised flips true after a successful Authorise.
	authorised bool
}

// Authorise opens the proxy session. Must be called before
// Handle. Returns the same error set as confirm.Authorize so
// the CLI can route.
func (h *WriteGatedHandler) Authorise(ctx context.Context) error {
	if h.authorised {
		return nil
	}
	m := SessionMutationWithGeneration(h.Target, h.Allowed, h.AllowedNodeIDs, h.AllowedCanonicalNodeIDs, h.AllowedCallMethods, h.TokenGeneration)
	if err := confirm.Authorize(ctx, m, h.SessionConfirm, h.Deriver, h.Auditor); err != nil {
		return err
	}
	h.authorised = true
	return nil
}

// ErrSessionNotAuthorised is returned by Handle when Authorise
// hasn't been called (or returned an error) yet.
var ErrSessionNotAuthorised = errors.New("opcua: write-gated proxy requires Authorise() first")

// Handle implements core.ProxyHandler.
func (h *WriteGatedHandler) Handle(ctx context.Context, client, upstream io.ReadWriter) error {
	if !h.authorised {
		return ErrSessionNotAuthorised
	}
	if h.Recorder != nil {
		client = h.Recorder.WrapClient(client)
		upstream = h.Recorder.WrapUpstream(upstream)
	}
	errs := make(chan error, 2)
	go func() { errs <- h.forward(client, upstream, client) }()
	go func() {
		_, err := io.Copy(client, upstream)
		errs <- err
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errs:
		return err
	}
}

// forward reads one UA-TCP frame at a time from the client and
// routes per policy. HEL/OPN/CLO pass unchanged; MSG is
// inspected and either forwarded or replaced with a
// ServiceFault.
func (h *WriteGatedHandler) forward(client io.Reader, upstream, clientWriter io.Writer) error {
	hdr := make([]byte, wire.HeaderSize)
	for {
		if _, err := io.ReadFull(client, hdr); err != nil {
			return err
		}
		header, err := wire.ParseHeader(hdr)
		if err != nil {
			return fmt.Errorf("opcua: parse header: %w", err)
		}
		bodyLen := int(header.Length) - wire.HeaderSize
		if bodyLen < 0 {
			return fmt.Errorf("opcua: negative body length %d", bodyLen)
		}
		body := make([]byte, bodyLen)
		if bodyLen > 0 {
			if _, err := io.ReadFull(client, body); err != nil {
				return err
			}
		}
		if err := h.routeFrame(header, body, upstream, clientWriter); err != nil {
			return err
		}
	}
}

// routeFrame is the per-frame policy decision.
func (h *WriteGatedHandler) routeFrame(header wire.Header, body []byte, upstream, clientWriter io.Writer) error {
	// HEL/OPN/CLO: transport-level frames. Always forward.
	// The gate only cares about service requests, which live
	// inside MSG chunks. An OPN that fails later on the server
	// side will surface as a server-emitted ERR on the return
	// path — we don't need to second-guess here.
	if header.Type != wire.MessageMessage {
		return writeFrame(upstream, header.Type, body)
	}
	typeID, ok := wire.ServiceTypeID(body)
	if !ok {
		// Unknown TypeId encoding → forward. We want to stay
		// conservative about refusing traffic we can't read;
		// refusing would break vendor clients that use
		// encodings outside TwoByte/FourByte for service
		// requests (none do in practice, but the safer default
		// is "forward unknown, refuse known-mutating").
		return writeFrame(upstream, header.Type, body)
	}
	if !wire.IsMutatingService(typeID) {
		return writeFrame(upstream, header.Type, body)
	}
	if !h.isAllowed(typeID) {
		// Service-TypeID allowlist denies → refuse.
		return writeServiceFault(clientWriter, body)
	}
	// Service-TypeID allows. If the per-NodeId gate is active,
	// further check every WriteValue's NodeId.
	if h.perNodeGateActive() && typeID == wire.TypeIDWriteRequest {
		if !h.writeRequestNodeAllowed(body) {
			return writeServiceFault(clientWriter, body)
		}
	}
	// Per-CallMethod gate active + this is a CallRequest → walk
	// every (ObjectID, MethodID) pair.
	if len(h.AllowedCallMethods) > 0 && typeID == wire.TypeIDCallRequest {
		if !h.callRequestAllMethodsAllowed(body) {
			return writeServiceFault(clientWriter, body)
		}
	}
	return writeFrame(upstream, header.Type, body)
}

// callRequestAllMethodsAllowed reports whether the CallRequest
// at `body` targets ONLY (ObjectID, MethodID) pairs in
// h.AllowedCallMethods. Returns false when:
//
//   - The MethodsToCall array can't be parsed (unknown encoding,
//     truncated, null array).
//   - ANY CallMethodRequest targets a pair outside the allowlist.
//
// Fail-closed on unparseable frames — same contract as
// writeRequestNodeAllowed.
func (h *WriteGatedHandler) callRequestAllMethodsAllowed(body []byte) bool {
	methods, ok := wire.CallRequestAllMethods(body)
	if !ok || len(methods) == 0 {
		return false
	}
	for _, cm := range methods {
		if !h.callMethodInAllowlist(cm) {
			return false
		}
	}
	return true
}

// callMethodInAllowlist reports whether one (Object, Method)
// pair matches any AllowedCallMethod entry. Both sides are
// compared on the canonical-string form (wire side from
// NodeIDValue.Canonical(), operator side pre-supplied).
func (h *WriteGatedHandler) callMethodInAllowlist(cm wire.CallMethod) bool {
	obj := cm.ObjectID.Canonical()
	mth := cm.MethodID.Canonical()
	if obj == "" || mth == "" {
		return false
	}
	for _, a := range h.AllowedCallMethods {
		if a.ObjectID == obj && a.MethodID == mth {
			return true
		}
	}
	return false
}

// perNodeGateActive reports whether EITHER per-NodeId allowlist
// is populated. Used by routeFrame to skip the per-node check
// when the operator only wants service-TypeID gating.
func (h *WriteGatedHandler) perNodeGateActive() bool {
	return len(h.AllowedNodeIDs) > 0 || len(h.AllowedCanonicalNodeIDs) > 0
}

// writeRequestNodeAllowed reports whether the WriteRequest at
// `body` targets ONLY NodeIds in the operator's allowlists.
// Returns false when:
//
//   - The NodesToWrite array can't be parsed (unknown encoding,
//     truncated, null array).
//   - ANY WriteValue targets a NodeId outside both the numeric
//     list (AllowedNodeIDs) and the canonical-string list
//     (AllowedCanonicalNodeIDs).
//
// History:
//   - v1.6 chunk 2: checked only the first WriteValue; batched
//     requests could slip past. Numeric encoding only.
//   - v1.12 chunk 2: walks EVERY WriteValue via numeric
//     WriteRequestAllNodes (still fail-closed on String/Guid/
//     ByteString).
//   - v1.12 chunk 3 (here): walks with the rich parser, so
//     String/Guid/ByteString NodeIDs can be admitted when they
//     match an AllowedCanonicalNodeID.
//
// Fail-closed semantics still apply: when the strict multi-node
// parser returns ok=false (unparseable WriteValue layout,
// unknown DataValue encoding, etc.), the whole RPC is refused.
// An attacker can't hide a write inside a complex-Variant
// WriteValue our parser can't walk.
func (h *WriteGatedHandler) writeRequestNodeAllowed(body []byte) bool {
	nodes, ok := wire.WriteRequestAllNodesRich(body)
	if !ok || len(nodes) == 0 {
		return false
	}
	for _, nid := range nodes {
		if !h.richNodeIDAllowed(nid) {
			return false
		}
	}
	return true
}

// richNodeIDAllowed reports whether one parsed NodeId matches
// either the numeric allowlist (for numeric encodings only) or
// the canonical-string allowlist (any encoding). The numeric
// fast path is kept so operators migrating from v1.6 keep their
// AllowedNodeIDs semantics unchanged.
func (h *WriteGatedHandler) richNodeIDAllowed(nid wire.NodeIDValue) bool {
	if nid.Kind == wire.NodeIDKindNumeric {
		for _, a := range h.AllowedNodeIDs {
			if a.Namespace == nid.Namespace && a.Identifier == nid.Numeric {
				return true
			}
		}
	}
	canon := nid.Canonical()
	if canon == "" {
		return false
	}
	for _, c := range h.AllowedCanonicalNodeIDs {
		if string(c) == canon {
			return true
		}
	}
	return false
}

// isAllowed reports whether the given service TypeId is in the
// session's allowlist.
func (h *WriteGatedHandler) isAllowed(typeID uint16) bool {
	for _, a := range h.Allowed {
		if a.TypeID == typeID {
			return true
		}
	}
	return false
}

// writeFrame emits a UA-TCP chunk with the given type + body.
// Manually wrapped so we don't depend on the wire package's
// internal `wrap` helper (which is private). The chunk is
// always final ('F') because the handler doesn't split service
// requests — if the client sent a continuation chunk, we
// forward it byte-for-byte already (body copy above).
func writeFrame(w io.Writer, mt wire.MessageType, body []byte) error {
	frame := make([]byte, wire.HeaderSize+len(body))
	copy(frame[0:3], string(mt))
	frame[3] = byte(wire.ChunkFinal)
	// #nosec G115 — header+body ≤ MaxMessageSize (1 MiB) by construction
	binary.LittleEndian.PutUint32(frame[4:8], uint32(wire.HeaderSize+len(body)))
	copy(frame[wire.HeaderSize:], body)
	_, err := w.Write(frame)
	return err
}

// Bad_UserAccessDenied status code (Part 4 Annex A). The upper
// 16 bits are the StatusCode severity+subcode; the lower 16 are
// informational.
const statusBadUserAccessDenied uint32 = 0x80100000

// ServiceFault TypeId — OPC-UA Part 4 §5.5.2.
const typeIDServiceFault uint16 = 397

// writeServiceFault emits a minimal UA ServiceFault MSG in
// response to a blocked request. Body layout:
//
//	[0..3]   SecureChannelId  — copied from the blocked request
//	[4..7]   TokenId          — copied
//	[8..11]  SequenceNumber   — +1 from the blocked request
//	[12..15] RequestId        — copied (binds reply → request)
//	[16..]   ExpandedNodeId   — FourByteNodeId, ns=0, id=397 (ServiceFault)
//	[...]    ResponseHeader   — Timestamp(now)=0 + RequestHandle(0) +
//	                            ServiceResult=BadUserAccessDenied +
//	                            ServiceDiagnostics(null) +
//	                            StringTable(empty) +
//	                            AdditionalHeader(null extension)
//
// Timestamps encoded as Windows-FILETIME ticks are zeroed
// because the gate does not need an accurate server clock and
// some minimal UA clients reject future timestamps > a few
// minutes drift. The response header wire layout here is
// deliberately minimal-but-valid per Part 6 §5.2.
func writeServiceFault(w io.Writer, blockedBody []byte) error {
	if len(blockedBody) < 16 {
		return fmt.Errorf("opcua: blocked body too short to mirror headers (%d)", len(blockedBody))
	}
	// Build response body.
	body := make([]byte, 0, 64)
	// Mirror SecureChannelId / TokenId / SequenceNumber + 1 / RequestId.
	body = append(body, blockedBody[0:4]...)
	body = append(body, blockedBody[4:8]...)
	seq := binary.LittleEndian.Uint32(blockedBody[8:12]) + 1
	var u32 [4]byte
	binary.LittleEndian.PutUint32(u32[:], seq)
	body = append(body, u32[:]...)
	body = append(body, blockedBody[12:16]...)
	// ExpandedNodeId: FourByteNodeId ns=0 id=397.
	body = append(body,
		byte(wire.NodeIDFourByte), // encoding
		0x00,                      // namespace
	)
	binary.LittleEndian.PutUint32(u32[:], 0) // temp reset
	var tid [2]byte
	binary.LittleEndian.PutUint16(tid[:], typeIDServiceFault)
	body = append(body, tid[:]...)
	// ResponseHeader:
	//   Timestamp (UtcTime = i64): 0
	body = append(body, make([]byte, 8)...)
	//   RequestHandle (u32): 0
	body = append(body, make([]byte, 4)...)
	//   ServiceResult (StatusCode u32 LE): BadUserAccessDenied
	binary.LittleEndian.PutUint32(u32[:], statusBadUserAccessDenied)
	body = append(body, u32[:]...)
	//   ServiceDiagnostics (DiagnosticInfo): encoding mask = 0x00 (nothing)
	body = append(body, 0x00)
	//   StringTable (i32 length prefix): -1 (null array)
	body = append(body, 0xFF, 0xFF, 0xFF, 0xFF)
	//   AdditionalHeader (ExtensionObject):
	//     TypeId NodeId: TwoByteNodeId id=0 (null)
	body = append(body, byte(wire.NodeIDTwoByte), 0x00)
	//     EncodingMask: 0x00 (no body)
	body = append(body, 0x00)
	return writeFrame(w, wire.MessageMessage, body)
}
