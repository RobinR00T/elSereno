package wire_test

import (
	"encoding/binary"
	"testing"

	"local/elsereno/internal/protocols/opcua/wire"
)

// bareWriteRequest builds a bare HTTPS-binding WriteRequest body (TypeId
// at offset 0, no opc.tcp MSG prefix). Mirrors the offensive opcua
// buildMultiMSGBody helper minus its 16-byte SecureChannel prefix, so
// the two encodings differ only by that prefix.
func bareWriteRequest(nodes []wire.NodeID) []byte {
	var buf []byte
	var u16 [2]byte
	var u32 [4]byte

	// Message TypeId: FourByte NodeId of WriteRequest.
	buf = append(buf, byte(wire.NodeIDFourByte), 0x00)
	binary.LittleEndian.PutUint16(u16[:], wire.TypeIDWriteRequest)
	buf = append(buf, u16[:]...)

	// RequestHeader.
	buf = append(buf, byte(wire.NodeIDTwoByte), 0x00) // AuthenticationToken null
	buf = append(buf, make([]byte, 8)...)             // Timestamp
	buf = append(buf, make([]byte, 4)...)             // RequestHandle
	buf = append(buf, make([]byte, 4)...)             // ReturnDiagnostics
	buf = append(buf, 0xFF, 0xFF, 0xFF, 0xFF)         // AuditEntryId null
	buf = append(buf, make([]byte, 4)...)             // TimeoutHint
	buf = append(buf, byte(wire.NodeIDTwoByte), 0x00) // AdditionalHeader NodeId null
	buf = append(buf, 0x00)                           // ExtensionObject encoding = 0

	// NodesToWrite array length + entries.
	binary.LittleEndian.PutUint32(u32[:], uint32(len(nodes))) // #nosec G115 -- test-bounded
	buf = append(buf, u32[:]...)
	for _, n := range nodes {
		nsByte := byte(n.Namespace) // #nosec G115 -- test NodeIDs use small namespaces
		buf = append(buf, byte(wire.NodeIDFourByte), nsByte)
		binary.LittleEndian.PutUint16(u16[:], uint16(n.Identifier)) // #nosec G115 -- test-bounded
		buf = append(buf, u16[:]...)
		binary.LittleEndian.PutUint32(u32[:], 13) // AttributeId = Value
		buf = append(buf, u32[:]...)
		buf = append(buf, 0xFF, 0xFF, 0xFF, 0xFF) // IndexRange null
		buf = append(buf, 0x00)                   // DataValue mask = 0
	}
	return buf
}

func TestServiceTypeIDHTTPS_GetEndpoints(t *testing.T) {
	bare := wire.EncodeGetEndpointsRequest("opc.https://plc.test:4843/")
	id, ok := wire.ServiceTypeIDHTTPS(bare)
	if !ok {
		t.Fatal("expected ok=true for a GetEndpointsRequest body")
	}
	if id != wire.TypeIDGetEndpointsRequest {
		t.Fatalf("TypeId = %d, want %d", id, wire.TypeIDGetEndpointsRequest)
	}
	if wire.IsMutatingService(id) {
		t.Error("GetEndpoints must not classify as a mutating service")
	}
}

func TestServiceTypeIDHTTPS_WriteRequest(t *testing.T) {
	bare := bareWriteRequest([]wire.NodeID{{Namespace: 2, Identifier: 42}})
	id, ok := wire.ServiceTypeIDHTTPS(bare)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if id != wire.TypeIDWriteRequest {
		t.Fatalf("TypeId = %d, want %d (WriteRequest)", id, wire.TypeIDWriteRequest)
	}
	if !wire.IsMutatingService(id) {
		t.Error("WriteRequest must classify as a mutating service")
	}
}

// TestHTTPSMatchesTCP asserts the HTTPS helper and the TCP parser agree
// once the 16-byte prefix is accounted for: the bare body spliced with
// a zero prefix must classify identically. This is the whole contract
// of the splice adapter.
func TestHTTPSMatchesTCP(t *testing.T) {
	bare := bareWriteRequest([]wire.NodeID{{Namespace: 5, Identifier: 99}})
	tcp := append(make([]byte, 16), bare...)

	idHTTPS, okH := wire.ServiceTypeIDHTTPS(bare)
	idTCP, okT := wire.ServiceTypeID(tcp)
	if okH != okT || idHTTPS != idTCP {
		t.Fatalf("HTTPS (%d,%t) != TCP (%d,%t)", idHTTPS, okH, idTCP, okT)
	}
}

func TestWriteRequestAllNodesRichHTTPS(t *testing.T) {
	want := []wire.NodeID{
		{Namespace: 2, Identifier: 42},
		{Namespace: 3, Identifier: 7},
	}
	bare := bareWriteRequest(want)
	nodes, ok := wire.WriteRequestAllNodesRichHTTPS(bare)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if len(nodes) != len(want) {
		t.Fatalf("len = %d, want %d", len(nodes), len(want))
	}
	for i, w := range want {
		if nodes[i].Kind != wire.NodeIDKindNumeric ||
			nodes[i].Namespace != w.Namespace || nodes[i].Numeric != w.Identifier {
			t.Errorf("nodes[%d] = %+v, want ns=%d id=%d", i, nodes[i], w.Namespace, w.Identifier)
		}
	}
}

func TestWriteRequestAllNodesRichHTTPS_FailClosed(t *testing.T) {
	// Truncated body (just a TypeId, no array) must fail closed.
	if _, ok := wire.WriteRequestAllNodesRichHTTPS([]byte{0x01, 0x00, 0xA1, 0x02}); ok {
		t.Error("truncated WriteRequest must return ok=false")
	}
	// Empty body must not panic and must fail closed.
	if _, ok := wire.WriteRequestAllNodesRichHTTPS(nil); ok {
		t.Error("nil body must return ok=false")
	}
}

func TestEncodeServiceFaultHTTPS(t *testing.T) {
	fault := wire.EncodeServiceFaultHTTPS(wire.StatusBadUserAccessDenied)

	// A ServiceFault is a bare message; its TypeId must decode as 397.
	id, ok := wire.ServiceTypeIDHTTPS(fault)
	if !ok || id != wire.TypeIDServiceFault {
		t.Fatalf("fault TypeId = (%d,%t), want %d", id, ok, wire.TypeIDServiceFault)
	}

	// ServiceResult sits after TypeId(4) + Timestamp(8) + RequestHandle(4).
	const serviceResultOff = 4 + 8 + 4
	if len(fault) < serviceResultOff+4 {
		t.Fatalf("fault too short: %d bytes", len(fault))
	}
	got := binary.LittleEndian.Uint32(fault[serviceResultOff : serviceResultOff+4])
	if got != wire.StatusBadUserAccessDenied {
		t.Errorf("ServiceResult = 0x%08X, want 0x%08X", got, wire.StatusBadUserAccessDenied)
	}
}

// FuzzServiceTypeIDHTTPS guards the splice adapter against panics on
// adversarial short / malformed bodies (the underlying TCP parsers are
// already fuzzed; this proves the 16-byte prepend never over-reads).
func FuzzServiceTypeIDHTTPS(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x01, 0x00, 0xA1, 0x02})
	f.Fuzz(func(_ *testing.T, b []byte) {
		_, _ = wire.ServiceTypeIDHTTPS(b)
		_, _ = wire.WriteRequestAllNodesRichHTTPS(b)
		_, _ = wire.CallRequestAllMethodsHTTPS(b)
	})
}
