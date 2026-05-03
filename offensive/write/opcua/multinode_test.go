//go:build offensive

package opcua_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"local/elsereno/internal/protocols/opcua/wire"
	"local/elsereno/offensive/confirm"
	opwrite "local/elsereno/offensive/write/opcua"
)

// buildMultiMSGBody crafts a WriteRequest MSG body carrying N
// WriteValues. Each WriteValue:
//
//	NodeId (FourByte):      4 bytes (0x01 + ns + id little-endian)
//	AttributeId (UInt32):   4 bytes
//	IndexRange (String -1): 4 bytes (null)
//	DataValue (mask=0):     1 byte (no Value, no timestamps)
//
// So each WriteValue is exactly 13 bytes.
func buildMultiMSGBody(nodes []opwrite.AllowedNodeID) []byte {
	buf := make([]byte, 16) // SCId + TokenId + SeqNo + ReqId

	// TypeID prefix (FourByte NodeId: encoding + ns + u16 id)
	buf = append(buf, byte(wire.NodeIDFourByte), 0x00)
	var u16 [2]byte
	binary.LittleEndian.PutUint16(u16[:], wire.TypeIDWriteRequest)
	buf = append(buf, u16[:]...)

	// RequestHeader (identical to buildMSGBody's layout)
	buf = append(buf, byte(wire.NodeIDTwoByte), 0x00) // AuthToken
	buf = append(buf, make([]byte, 8)...)             // Timestamp
	buf = append(buf, make([]byte, 4)...)             // RequestHandle
	buf = append(buf, make([]byte, 4)...)             // ReturnDiag
	buf = append(buf, 0xFF, 0xFF, 0xFF, 0xFF)         // AuditEntryId null
	buf = append(buf, make([]byte, 4)...)             // TimeoutHint
	buf = append(buf, byte(wire.NodeIDTwoByte), 0x00) // AdditionalHeader NodeId
	buf = append(buf, 0x00)                           // ExtensionObject encoding=0

	// NodesToWrite array length
	var u32 [4]byte
	binary.LittleEndian.PutUint32(u32[:], uint32(len(nodes)&0xFFFFFFFF)) // #nosec G115 -- test-bounded slice length
	buf = append(buf, u32[:]...)

	for _, n := range nodes {
		// NodeId (FourByte: encoding + ns + id LE)
		buf = append(buf, byte(wire.NodeIDFourByte), byte(n.Namespace&0xFF))
		binary.LittleEndian.PutUint16(u16[:], uint16(n.Identifier&0xFFFF))
		buf = append(buf, u16[:]...)
		// AttributeId (u32 = 13 for Value attribute)
		binary.LittleEndian.PutUint32(u32[:], 13)
		buf = append(buf, u32[:]...)
		// IndexRange null
		buf = append(buf, 0xFF, 0xFF, 0xFF, 0xFF)
		// DataValue mask = 0 (no Value, no timestamps). Not
		// spec-realistic for an actual write but sufficient for
		// the gate to walk the entry.
		buf = append(buf, 0x00)
	}
	return buf
}

// wrapMultiMSG prefixes the MSG chunk header.
func wrapMultiMSG(body []byte) []byte {
	total := wire.HeaderSize + len(body)
	frame := make([]byte, total)
	copy(frame[0:3], "MSG")
	frame[3] = byte(wire.ChunkFinal)
	binary.LittleEndian.PutUint32(frame[4:8], uint32(total)) // #nosec G115 -- test-bounded
	copy(frame[wire.HeaderSize:], body)
	return frame
}

// driveMultiNodeSession authorises a handler with the given
// service + per-NodeId allowlists and returns (client, upstream
// recorder). Reads on the recorder go through the safeBuffer
// mutex — direct .buf access would race the io.Copy goroutine.
func driveMultiNodeSession(t *testing.T, svcs []opwrite.AllowedService, nodeIDs []opwrite.AllowedNodeID) (net.Conn, *safeBuffer) {
	t.Helper()
	target := "plc.test:4840"
	h := &opwrite.WriteGatedHandler{
		Target:         target,
		Allowed:        svcs,
		AllowedNodeIDs: nodeIDs,
		Deriver:        &fakeDeriverNode{key: []byte(testDeriverKeyNode)},
		Auditor:        &fakeAuditorNode{},
	}
	mut := opwrite.SessionMutationWithNodeIDs(target, svcs, nodeIDs)
	tok, err := confirm.ExpectedToken(mut, &fakeDeriverNode{key: []byte(testDeriverKeyNode)})
	if err != nil {
		t.Fatal(err)
	}
	h.SessionConfirm = confirm.Confirm{
		AcceptsWrites: true,
		ConfirmTarget: target,
		ConfirmToken:  tok,
	}
	if err := h.Authorise(context.Background()); err != nil {
		t.Fatal(err)
	}
	clientPipe, handlerClientSide := net.Pipe()
	upstreamReaderSide, upstreamWriterSide := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = clientPipe.Close()
		_ = handlerClientSide.Close()
		_ = upstreamReaderSide.Close()
		_ = upstreamWriterSide.Close()
	})
	upstreamBuf := &safeBuffer{}
	go func() { _, _ = io.Copy(upstreamBuf, upstreamReaderSide) }()
	go func() { _ = h.Handle(ctx, handlerClientSide, upstreamWriterSide) }()
	return clientPipe, upstreamBuf
}

// ---- Wire parser: WriteRequestAllNodes -----------------------

func TestWriteRequestAllNodes_SingleNode(t *testing.T) {
	body := buildMultiMSGBody([]opwrite.AllowedNodeID{
		{Namespace: 2, Identifier: 42},
	})
	nodes, ok := wire.WriteRequestAllNodes(body)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if len(nodes) != 1 {
		t.Fatalf("len=%d, want 1", len(nodes))
	}
	if nodes[0].Namespace != 2 || nodes[0].Identifier != 42 {
		t.Errorf("nodes[0] = %+v", nodes[0])
	}
}

func TestWriteRequestAllNodes_Multiple(t *testing.T) {
	body := buildMultiMSGBody([]opwrite.AllowedNodeID{
		{Namespace: 2, Identifier: 42},
		{Namespace: 3, Identifier: 100},
		{Namespace: 2, Identifier: 7},
	})
	nodes, ok := wire.WriteRequestAllNodes(body)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if len(nodes) != 3 {
		t.Fatalf("len=%d, want 3", len(nodes))
	}
	if nodes[0].Identifier != 42 || nodes[1].Identifier != 100 || nodes[2].Identifier != 7 {
		t.Errorf("document order not preserved: %+v", nodes)
	}
}

func TestWriteRequestAllNodes_EmptyArrayFails(t *testing.T) {
	body := buildMultiMSGBody(nil)
	_, ok := wire.WriteRequestAllNodes(body)
	if ok {
		t.Fatal("empty NodesToWrite array should return ok=false")
	}
}

func TestWriteRequestAllNodes_TruncatedFails(t *testing.T) {
	// Build a 3-node body, then truncate mid-second-WriteValue.
	body := buildMultiMSGBody([]opwrite.AllowedNodeID{
		{Namespace: 1, Identifier: 1},
		{Namespace: 2, Identifier: 2},
		{Namespace: 3, Identifier: 3},
	})
	// Keep everything through the end of the 1st WriteValue (13 b)
	// but truncate somewhere in the 2nd. Each WriteValue is 13 b.
	// Truncate to cut off the 2nd's DataValue.
	truncatedLen := len(body) - 5
	_, ok := wire.WriteRequestAllNodes(body[:truncatedLen])
	if ok {
		t.Fatal("truncated body should return ok=false")
	}
}

// ---- Gate E2E: multi-node refusal ---------------------------

// TestGateMultiNode_AllAllowed — every WriteValue's NodeId is
// in the allowlist → forward.
func TestGateMultiNode_AllAllowed(t *testing.T) {
	svcs := []opwrite.AllowedService{{TypeID: wire.TypeIDWriteRequest}}
	nodeIDs := []opwrite.AllowedNodeID{
		{Namespace: 2, Identifier: 42},
		{Namespace: 2, Identifier: 43},
		{Namespace: 3, Identifier: 100},
	}
	client, upstreamBuf := driveMultiNodeSession(t, svcs, nodeIDs)

	body := buildMultiMSGBody([]opwrite.AllowedNodeID{
		{Namespace: 2, Identifier: 42},
		{Namespace: 2, Identifier: 43},
	})
	_, _ = client.Write(wrapMultiMSG(body))

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if upstreamBuf.Len() > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if upstreamBuf.Len() == 0 {
		t.Fatal("upstream saw nothing for a fully-allowed multi-node WriteRequest")
	}
}

// TestGateMultiNode_OneUnknownRefuses — even ONE NodeId outside
// the allowlist refuses the WHOLE request. This is the v1.6-
// carry-over bug fix: the old gate only checked the FIRST
// WriteValue, letting a multi-node batch slip the 2nd/Nth past.
func TestGateMultiNode_OneUnknownRefuses(t *testing.T) {
	svcs := []opwrite.AllowedService{{TypeID: wire.TypeIDWriteRequest}}
	nodeIDs := []opwrite.AllowedNodeID{
		{Namespace: 2, Identifier: 42}, // only ns=2;i=42 allowed
	}
	client, upstreamBuf := driveMultiNodeSession(t, svcs, nodeIDs)

	// Request batches the allowed node FIRST (v1.6 gate would
	// have let this through) with a forbidden node SECOND.
	body := buildMultiMSGBody([]opwrite.AllowedNodeID{
		{Namespace: 2, Identifier: 42},  // OK
		{Namespace: 2, Identifier: 999}, // FORBIDDEN
	})
	_, _ = client.Write(wrapMultiMSG(body))

	_ = client.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	rbuf := make([]byte, 2048)
	n, err := client.Read(rbuf)
	if err != nil {
		t.Fatalf("read fault back: %v", err)
	}
	if n == 0 || !bytes.HasPrefix(rbuf[:n], []byte("MSG")) {
		t.Fatalf("expected MSG (ServiceFault) refusal, got % x", rbuf[:8])
	}
	time.Sleep(50 * time.Millisecond)
	if upstreamBuf.Len() != 0 {
		t.Fatalf("v1.12 fix regression: multi-node batch with one forbidden NodeId should refuse, but upstream saw %d bytes", upstreamBuf.Len())
	}
}

// TestGateMultiNode_DuplicateNodesPass — the same NodeId twice
// in one request is fine as long as both are in the allowlist.
func TestGateMultiNode_DuplicateNodesPass(t *testing.T) {
	svcs := []opwrite.AllowedService{{TypeID: wire.TypeIDWriteRequest}}
	nodeIDs := []opwrite.AllowedNodeID{{Namespace: 2, Identifier: 42}}
	client, upstreamBuf := driveMultiNodeSession(t, svcs, nodeIDs)

	body := buildMultiMSGBody([]opwrite.AllowedNodeID{
		{Namespace: 2, Identifier: 42},
		{Namespace: 2, Identifier: 42},
		{Namespace: 2, Identifier: 42},
	})
	_, _ = client.Write(wrapMultiMSG(body))

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if upstreamBuf.Len() > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if upstreamBuf.Len() == 0 {
		t.Fatal("triplicate-same-node should have passed")
	}
}
