//go:build offensive

package opcua_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"local/elsereno/internal/protocols/opcua/wire"
	"local/elsereno/offensive/confirm"
	opwrite "local/elsereno/offensive/write/opcua"
)

// safeBuffer is a bytes.Buffer wrapped in a mutex so the
// test-side goroutine can poll Len() / Bytes() without racing
// the recorder goroutine that's populating it.
type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *safeBuffer) Write(b []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(b)
}

func (s *safeBuffer) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Len()
}

func (s *safeBuffer) Bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]byte, s.buf.Len())
	copy(out, s.buf.Bytes())
	return out
}

// ---- AllowlistHash with NodeIDs -------------------------------

func TestAllowlistHashWithNodeIDs_EmptyNodesMatchesV12(t *testing.T) {
	// When nodeIDs is nil/empty the v1.6 hash must equal the
	// v1.2 AllowlistHash. This preserves operator tokens for
	// anyone not opting into per-node gating.
	svcs := []opwrite.AllowedService{{TypeID: wire.TypeIDWriteRequest}}
	h12 := opwrite.AllowlistHash("host:4840", svcs)
	h16 := opwrite.AllowlistHashWithNodeIDs("host:4840", svcs, nil)
	if !bytes.Equal(h12[:], h16[:]) {
		t.Fatalf("v1.6 hash with empty NodeIDs differs from v1.2: %x vs %x", h16, h12)
	}
}

func TestAllowlistHashWithNodeIDs_NodesChangeHash(t *testing.T) {
	svcs := []opwrite.AllowedService{{TypeID: wire.TypeIDWriteRequest}}
	nodes := []opwrite.AllowedNodeID{{Namespace: 2, Identifier: 42}}
	h12 := opwrite.AllowlistHash("host:4840", svcs)
	h16 := opwrite.AllowlistHashWithNodeIDs("host:4840", svcs, nodes)
	if bytes.Equal(h12[:], h16[:]) {
		t.Fatal("v1.6 hash with NodeIDs must differ from v1.2 hash")
	}
}

func TestAllowlistHashWithNodeIDs_OrderInsensitive(t *testing.T) {
	svcs := []opwrite.AllowedService{{TypeID: wire.TypeIDWriteRequest}}
	a := []opwrite.AllowedNodeID{
		{Namespace: 2, Identifier: 42},
		{Namespace: 3, Identifier: 100},
	}
	b := []opwrite.AllowedNodeID{
		{Namespace: 3, Identifier: 100},
		{Namespace: 2, Identifier: 42},
	}
	h1 := opwrite.AllowlistHashWithNodeIDs("host:4840", svcs, a)
	h2 := opwrite.AllowlistHashWithNodeIDs("host:4840", svcs, b)
	if !bytes.Equal(h1[:], h2[:]) {
		t.Fatal("hash depends on NodeID input order")
	}
}

// ---- WriteRequestFirstNode wire parser ------------------------

// buildMSGBody crafts a MSG chunk body with:
//   - 16 bytes fixed header (SCId, TokenId, SeqNo, ReqId — all 0)
//   - 4 bytes FourByte NodeId TypeID (always WriteRequest 673
//     for this helper; WriteRequest is the only service whose
//     per-NodeId gate fires)
//   - minimal RequestHeader
//   - NodesToWrite array with one WriteValue whose NodeId is (ns,id)
//
// Each section is the shortest valid shape I could construct
// without relying on a full UA encoder.
func buildMSGBody(firstNode opwrite.AllowedNodeID) []byte {
	buf := make([]byte, 16) // SCId + TokenId + SeqNo + ReqId, all 0

	// TypeID as FourByte NodeId: encoding(1) + ns(1) + id(u16 LE)
	buf = append(buf, byte(wire.NodeIDFourByte), 0x00)
	var u16 [2]byte
	binary.LittleEndian.PutUint16(u16[:], wire.TypeIDWriteRequest)
	buf = append(buf, u16[:]...)

	// RequestHeader:
	//   AuthenticationToken (TwoByte null = 2 bytes)
	buf = append(buf, byte(wire.NodeIDTwoByte), 0x00)
	//   Timestamp (UtcTime i64 = 8 bytes, all 0)
	buf = append(buf, make([]byte, 8)...)
	//   RequestHandle (u32 = 4 bytes, 0)
	buf = append(buf, make([]byte, 4)...)
	//   ReturnDiagnostics (u32 = 4 bytes, 0)
	buf = append(buf, make([]byte, 4)...)
	//   AuditEntryId (String null = 0xFFFFFFFF = 4 bytes)
	buf = append(buf, 0xFF, 0xFF, 0xFF, 0xFF)
	//   TimeoutHint (u32 = 4 bytes, 0)
	buf = append(buf, make([]byte, 4)...)
	//   AdditionalHeader ExtensionObject:
	//     TypeId (TwoByte null = 2 bytes)
	buf = append(buf, byte(wire.NodeIDTwoByte), 0x00)
	//     Encoding (1 byte = 0, no body)
	buf = append(buf, 0x00)

	// NodesToWrite array:
	//   Length prefix (u32 LE = 1)
	var u32 [4]byte
	binary.LittleEndian.PutUint32(u32[:], 1)
	buf = append(buf, u32[:]...)
	// First WriteValue: NodeId (FourByte: encoding + ns + id)
	// Tests intentionally use small ns/id values so narrowing
	// uint16→byte and uint32→uint16 is safe; the explicit mask
	// keeps gosec happy.
	buf = append(buf, byte(wire.NodeIDFourByte), byte(firstNode.Namespace&0xFF))
	binary.LittleEndian.PutUint16(u16[:], uint16(firstNode.Identifier&0xFFFF))
	buf = append(buf, u16[:]...)
	// Rest of WriteValue (AttributeId u32, IndexRange String null,
	// Value DataValue) — not inspected, pad with zeros.
	buf = append(buf, make([]byte, 4+4+1)...)
	return buf
}

func TestWriteRequestFirstNode_FourByteNumeric(t *testing.T) {
	body := buildMSGBody(opwrite.AllowedNodeID{Namespace: 2, Identifier: 42})
	nid, n, ok := wire.WriteRequestFirstNode(body)
	if !ok {
		t.Fatal("WriteRequestFirstNode: expected ok=true")
	}
	if n != 1 {
		t.Fatalf("node count = %d, want 1", n)
	}
	if nid.Namespace != 2 || nid.Identifier != 42 {
		t.Fatalf("NodeID = ns=%d;i=%d, want ns=2;i=42", nid.Namespace, nid.Identifier)
	}
}

func TestWriteRequestFirstNode_ShortFrameFails(t *testing.T) {
	_, _, ok := wire.WriteRequestFirstNode([]byte{0x00, 0x00, 0x00})
	if ok {
		t.Fatal("short frame: expected ok=false")
	}
}

// ---- End-to-end: per-NodeId gate via the handler --------------

type fakeDeriverNode struct{ key []byte }

func (f *fakeDeriverNode) Derive(_ string, out []byte) error {
	copy(out, f.key)
	return nil
}

type fakeAuditorNode struct{}

func (*fakeAuditorNode) Record(_ context.Context, _ confirm.AuditEvent) error { return nil }

const testDeriverKeyNode = "test-key-32-byte-long--------"

func mintTokenNodeGate(t *testing.T, target string, svcs []opwrite.AllowedService, nodeIDs []opwrite.AllowedNodeID) string {
	t.Helper()
	mut := opwrite.SessionMutationWithNodeIDs(target, svcs, nodeIDs)
	tok, err := confirm.ExpectedToken(mut, &fakeDeriverNode{key: []byte(testDeriverKeyNode)})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// driveNodeGateSession wires a handler + two net.Pipe pairs
// (client ↔ handler ↔ upstream). Returns (clientConn,
// upstreamWrittenBytes) so tests can assert on the upstream
// side's view of forwarded bytes.
func driveNodeGateSession(t *testing.T, svcs []opwrite.AllowedService, nodeIDs []opwrite.AllowedNodeID) (net.Conn, *safeBuffer) {
	t.Helper()
	target := "plc.test:4840"
	h := &opwrite.WriteGatedHandler{
		Target:         target,
		Allowed:        svcs,
		AllowedNodeIDs: nodeIDs,
		Deriver:        &fakeDeriverNode{key: []byte(testDeriverKeyNode)},
		Auditor:        &fakeAuditorNode{},
		SessionConfirm: confirm.Confirm{
			AcceptsWrites: true,
			ConfirmTarget: target,
			ConfirmToken:  mintTokenNodeGate(t, target, svcs, nodeIDs),
		},
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

// wrapMSG prefixes an MSG chunk header so the handler's parser
// can read the frame.
func wrapMSG(body []byte) []byte {
	total := wire.HeaderSize + len(body)
	frame := make([]byte, total)
	copy(frame[0:3], "MSG")
	frame[3] = byte(wire.ChunkFinal)
	binary.LittleEndian.PutUint32(frame[4:8], uint32(total)) //nolint:gosec // test-bounded sizes
	copy(frame[wire.HeaderSize:], body)
	return frame
}

func TestGate_NodeIDAllowed(t *testing.T) {
	svcs := []opwrite.AllowedService{{TypeID: wire.TypeIDWriteRequest}}
	nodeIDs := []opwrite.AllowedNodeID{{Namespace: 2, Identifier: 42}}
	client, upstreamBuf := driveNodeGateSession(t, svcs, nodeIDs)

	body := buildMSGBody(opwrite.AllowedNodeID{Namespace: 2, Identifier: 42})
	_, _ = client.Write(wrapMSG(body))

	// Wait for upstream to see the forwarded frame.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if upstreamBuf.Len() > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if upstreamBuf.Len() == 0 {
		t.Fatal("upstream saw nothing for allowed NodeID")
	}
	// First 3 bytes are "MSG".
	if !bytes.HasPrefix(upstreamBuf.Bytes(), []byte("MSG")) {
		t.Fatalf("upstream prefix wrong: % x", upstreamBuf.Bytes()[:8])
	}
}

func TestGate_NodeIDBlockedGetsServiceFault(t *testing.T) {
	svcs := []opwrite.AllowedService{{TypeID: wire.TypeIDWriteRequest}}
	// Allow ns=2;i=42 but the client targets ns=2;i=99 — denied.
	nodeIDs := []opwrite.AllowedNodeID{{Namespace: 2, Identifier: 42}}
	client, upstreamBuf := driveNodeGateSession(t, svcs, nodeIDs)

	body := buildMSGBody(opwrite.AllowedNodeID{Namespace: 2, Identifier: 99})
	_, _ = client.Write(wrapMSG(body))

	// Client should receive a ServiceFault.
	_ = client.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 1024)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("read fault back: %v", err)
	}
	if !bytes.HasPrefix(buf[:n], []byte("MSG")) {
		t.Fatalf("fault prefix wrong: % x", buf[:8])
	}
	// Upstream should NOT have seen anything.
	time.Sleep(50 * time.Millisecond)
	if upstreamBuf.Len() != 0 {
		t.Fatalf("upstream saw bytes for a blocked NodeID: %d", upstreamBuf.Len())
	}
}

func TestGate_EmptyNodeIDListFallsBackToServiceLevelGate(t *testing.T) {
	// Empty NodeIDs → v1.2 behaviour: any WriteRequest passes
	// as long as the service is in the allowlist.
	svcs := []opwrite.AllowedService{{TypeID: wire.TypeIDWriteRequest}}
	client, upstreamBuf := driveNodeGateSession(t, svcs, nil)

	body := buildMSGBody(opwrite.AllowedNodeID{Namespace: 99, Identifier: 9999})
	_, _ = client.Write(wrapMSG(body))

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if upstreamBuf.Len() > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if upstreamBuf.Len() == 0 {
		t.Fatal("v1.2 fallback: expected upstream to see WriteRequest when AllowedNodeIDs is nil")
	}
}
