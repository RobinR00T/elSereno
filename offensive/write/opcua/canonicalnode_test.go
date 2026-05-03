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

// ---- Hash ladder: rich variant degrades to v1.6 / v1.2 -------

func TestAllowlistHashWithRichNodeIDs_EmptyCanonicalMatchesV16(t *testing.T) {
	// Rich hash with empty canonical list must equal the v1.6
	// hash with the same numeric list. Preserves tokens minted
	// before v1.12.
	svcs := []opwrite.AllowedService{{TypeID: wire.TypeIDWriteRequest}}
	nodes := []opwrite.AllowedNodeID{{Namespace: 2, Identifier: 42}}
	h16 := opwrite.AllowlistHashWithNodeIDs("host:4840", svcs, nodes)
	hRich := opwrite.AllowlistHashWithRichNodeIDs("host:4840", svcs, nodes, nil)
	if !bytes.Equal(h16[:], hRich[:]) {
		t.Fatalf("rich hash with empty canonical differs from v1.6: %x vs %x", hRich, h16)
	}
}

func TestAllowlistHashWithRichNodeIDs_EmptyBothMatchesV12(t *testing.T) {
	// Rich hash with empty numeric + canonical collapses all the
	// way to v1.2. Two-layer backwards-compat ladder.
	svcs := []opwrite.AllowedService{{TypeID: wire.TypeIDWriteRequest}}
	h12 := opwrite.AllowlistHash("host:4840", svcs)
	hRich := opwrite.AllowlistHashWithRichNodeIDs("host:4840", svcs, nil, nil)
	if !bytes.Equal(h12[:], hRich[:]) {
		t.Fatalf("rich hash with empty numeric+canonical differs from v1.2: %x vs %x", hRich, h12)
	}
}

func TestAllowlistHashWithRichNodeIDs_CanonicalChangesHash(t *testing.T) {
	svcs := []opwrite.AllowedService{{TypeID: wire.TypeIDWriteRequest}}
	canon := []opwrite.AllowedCanonicalNodeID{"ns=2;s=Temperature"}
	h16 := opwrite.AllowlistHashWithNodeIDs("host:4840", svcs, nil)
	hRich := opwrite.AllowlistHashWithRichNodeIDs("host:4840", svcs, nil, canon)
	if bytes.Equal(h16[:], hRich[:]) {
		t.Fatal("rich hash with canonical NodeID must differ from v1.6 hash")
	}
}

func TestAllowlistHashWithRichNodeIDs_OrderInsensitive(t *testing.T) {
	svcs := []opwrite.AllowedService{{TypeID: wire.TypeIDWriteRequest}}
	a := []opwrite.AllowedCanonicalNodeID{
		"ns=2;s=Temperature",
		"ns=3;g=6B29FC40CA471067B31D00DD010662DA",
		"ns=4;b=DEADBEEF",
	}
	b := []opwrite.AllowedCanonicalNodeID{
		"ns=4;b=DEADBEEF",
		"ns=2;s=Temperature",
		"ns=3;g=6B29FC40CA471067B31D00DD010662DA",
	}
	h1 := opwrite.AllowlistHashWithRichNodeIDs("host:4840", svcs, nil, a)
	h2 := opwrite.AllowlistHashWithRichNodeIDs("host:4840", svcs, nil, b)
	if !bytes.Equal(h1[:], h2[:]) {
		t.Fatal("rich hash depends on canonical input order")
	}
}

// TestAllowlistHashWithRichNodeIDs_LengthPrefixPreventsCollision —
// canonical strings are length-prefixed in the hash so two lists
// whose concatenation would be byte-identical still produce
// different hashes. Guards against "ns=1;s=A" + "B" colliding
// with "ns=1;s=AB" + "" (or similar attacker-crafted near-
// collisions).
func TestAllowlistHashWithRichNodeIDs_LengthPrefixPreventsCollision(t *testing.T) {
	svcs := []opwrite.AllowedService{{TypeID: wire.TypeIDWriteRequest}}
	a := []opwrite.AllowedCanonicalNodeID{"ns=1;s=AB", "ns=2;s=C"}
	b := []opwrite.AllowedCanonicalNodeID{"ns=1;s=A", "ns=2;s=BC"} // same bytes without length prefix
	h1 := opwrite.AllowlistHashWithRichNodeIDs("host:4840", svcs, nil, a)
	h2 := opwrite.AllowlistHashWithRichNodeIDs("host:4840", svcs, nil, b)
	if bytes.Equal(h1[:], h2[:]) {
		t.Fatal("hash collision between concatenation-compatible lists; length prefix not honoured")
	}
}

// ---- Rich wire parser: WriteRequestAllNodesRich -------------

func TestWriteRequestAllNodesRich_StringNodeID(t *testing.T) {
	body := buildMultiMSGBodyRich([]wire.NodeIDValue{
		{Namespace: 2, Kind: wire.NodeIDKindString, String: "Temperature"},
	})
	nodes, ok := wire.WriteRequestAllNodesRich(body)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if len(nodes) != 1 {
		t.Fatalf("len=%d, want 1", len(nodes))
	}
	if nodes[0].Canonical() != "ns=2;s=Temperature" {
		t.Errorf("canonical=%q, want ns=2;s=Temperature", nodes[0].Canonical())
	}
}

func TestWriteRequestAllNodesRich_GuidNodeID(t *testing.T) {
	var guid [16]byte
	for i := range guid {
		guid[i] = byte(0x10 + i)
	}
	body := buildMultiMSGBodyRich([]wire.NodeIDValue{
		{Namespace: 1, Kind: wire.NodeIDKindGUID, GUID: guid},
	})
	nodes, ok := wire.WriteRequestAllNodesRich(body)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if len(nodes) != 1 {
		t.Fatalf("len=%d, want 1", len(nodes))
	}
	want := "ns=1;g=101112131415161718191A1B1C1D1E1F"
	if nodes[0].Canonical() != want {
		t.Errorf("canonical=%q, want %q", nodes[0].Canonical(), want)
	}
}

func TestWriteRequestAllNodesRich_ByteStringNodeID(t *testing.T) {
	body := buildMultiMSGBodyRich([]wire.NodeIDValue{
		{Namespace: 3, Kind: wire.NodeIDKindByteString, Bytes: []byte{0xDE, 0xAD, 0xBE, 0xEF}},
	})
	nodes, ok := wire.WriteRequestAllNodesRich(body)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if len(nodes) != 1 {
		t.Fatalf("len=%d, want 1", len(nodes))
	}
	if nodes[0].Canonical() != "ns=3;b=DEADBEEF" {
		t.Errorf("canonical=%q, want ns=3;b=DEADBEEF", nodes[0].Canonical())
	}
}

func TestWriteRequestAllNodesRich_MixedEncodings(t *testing.T) {
	var guid [16]byte
	for i := range guid {
		guid[i] = 0xAA
	}
	body := buildMultiMSGBodyRich([]wire.NodeIDValue{
		{Namespace: 2, Kind: wire.NodeIDKindNumeric, Numeric: 42},
		{Namespace: 2, Kind: wire.NodeIDKindString, String: "Pressure"},
		{Namespace: 1, Kind: wire.NodeIDKindGUID, GUID: guid},
		{Namespace: 4, Kind: wire.NodeIDKindByteString, Bytes: []byte{0x01, 0x02}},
	})
	nodes, ok := wire.WriteRequestAllNodesRich(body)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if len(nodes) != 4 {
		t.Fatalf("len=%d, want 4", len(nodes))
	}
	expected := []string{
		"ns=2;i=42",
		"ns=2;s=Pressure",
		"ns=1;g=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"ns=4;b=0102",
	}
	for i, e := range expected {
		if nodes[i].Canonical() != e {
			t.Errorf("nodes[%d] = %q, want %q", i, nodes[i].Canonical(), e)
		}
	}
}

func TestWriteRequestAllNodesRich_TruncatedStringFails(t *testing.T) {
	body := buildMultiMSGBodyRich([]wire.NodeIDValue{
		{Namespace: 2, Kind: wire.NodeIDKindString, String: "LongVariableName"},
	})
	// Chop off the last 4 bytes (mid-string).
	truncated := body[:len(body)-4]
	_, ok := wire.WriteRequestAllNodesRich(truncated)
	if ok {
		t.Fatal("truncated string NodeID should return ok=false")
	}
}

// ---- E2E gate: rich NodeID allowlist --------------------------

// driveRichNodeSession authorises a handler with both numeric +
// canonical allowlists.
func driveRichNodeSession(t *testing.T, svcs []opwrite.AllowedService, nids []opwrite.AllowedNodeID, canon []opwrite.AllowedCanonicalNodeID) (net.Conn, *safeBuffer) {
	t.Helper()
	target := "plc.test:4840"
	h := &opwrite.WriteGatedHandler{
		Target:                  target,
		Allowed:                 svcs,
		AllowedNodeIDs:          nids,
		AllowedCanonicalNodeIDs: canon,
		Deriver:                 &fakeDeriverNode{key: []byte(testDeriverKeyNode)},
		Auditor:                 &fakeAuditorNode{},
	}
	mut := opwrite.SessionMutationWithRichNodeIDs(target, svcs, nids, canon)
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

func TestGateRichNode_StringAllowlistPass(t *testing.T) {
	svcs := []opwrite.AllowedService{{TypeID: wire.TypeIDWriteRequest}}
	canon := []opwrite.AllowedCanonicalNodeID{"ns=2;s=Temperature"}
	client, upstreamBuf := driveRichNodeSession(t, svcs, nil, canon)

	body := buildMultiMSGBodyRich([]wire.NodeIDValue{
		{Namespace: 2, Kind: wire.NodeIDKindString, String: "Temperature"},
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
		t.Fatal("upstream saw nothing for allowed string-NodeId WriteRequest")
	}
}

func TestGateRichNode_GuidAllowlistPass(t *testing.T) {
	svcs := []opwrite.AllowedService{{TypeID: wire.TypeIDWriteRequest}}
	var guid [16]byte
	for i := range guid {
		guid[i] = byte(0x10 + i)
	}
	canon := []opwrite.AllowedCanonicalNodeID{"ns=1;g=101112131415161718191A1B1C1D1E1F"}
	client, upstreamBuf := driveRichNodeSession(t, svcs, nil, canon)

	body := buildMultiMSGBodyRich([]wire.NodeIDValue{
		{Namespace: 1, Kind: wire.NodeIDKindGUID, GUID: guid},
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
		t.Fatal("upstream saw nothing for allowed guid-NodeId WriteRequest")
	}
}

// TestGateRichNode_MixedBatchOneForbiddenRefuses — v1.12 chunk 3
// covers the String/Guid/ByteString encodings but still enforces
// the multi-node fail-closed semantics from chunk 2: a batch
// with any forbidden NodeId is fully refused.
func TestGateRichNode_MixedBatchOneForbiddenRefuses(t *testing.T) {
	svcs := []opwrite.AllowedService{{TypeID: wire.TypeIDWriteRequest}}
	nids := []opwrite.AllowedNodeID{{Namespace: 2, Identifier: 42}}
	canon := []opwrite.AllowedCanonicalNodeID{"ns=2;s=Allowed"}
	client, upstreamBuf := driveRichNodeSession(t, svcs, nids, canon)

	body := buildMultiMSGBodyRich([]wire.NodeIDValue{
		{Namespace: 2, Kind: wire.NodeIDKindNumeric, Numeric: 42},        // OK (numeric list)
		{Namespace: 2, Kind: wire.NodeIDKindString, String: "Allowed"},   // OK (canonical list)
		{Namespace: 2, Kind: wire.NodeIDKindString, String: "Forbidden"}, // DENY
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
		t.Fatalf("v1.12 chunk 3 regression: mixed batch with one forbidden string-NodeId should refuse, but upstream saw %d bytes", upstreamBuf.Len())
	}
}

// TestGateRichNode_NumericWireDoesNotAcceptCanonicalEntry — when
// the operator allowlists "ns=2;i=42" via the canonical list,
// a numeric-wire WriteValue for the same logical NodeID must
// STILL match. Confirms the richNodeIDAllowed matcher falls
// back to comparing .Canonical() against the canonical list.
func TestGateRichNode_NumericWireMatchesCanonicalEntry(t *testing.T) {
	svcs := []opwrite.AllowedService{{TypeID: wire.TypeIDWriteRequest}}
	// ONLY canonical allowlist — no numeric entries.
	canon := []opwrite.AllowedCanonicalNodeID{"ns=2;i=42"}
	client, upstreamBuf := driveRichNodeSession(t, svcs, nil, canon)

	body := buildMultiMSGBodyRich([]wire.NodeIDValue{
		{Namespace: 2, Kind: wire.NodeIDKindNumeric, Numeric: 42},
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
		t.Fatal("numeric wire NodeID should match its canonical-form allowlist entry")
	}
}

// ---- Helpers ---------------------------------------------------

// buildMultiMSGBodyRich builds a WriteRequest MSG body whose
// NodesToWrite carries the given rich NodeIDValues. Each
// WriteValue has:
//
//	NodeId (variable per encoding)
//	AttributeId (UInt32 = 13)
//	IndexRange (String -1, 4 bytes)
//	DataValue (mask=0, 1 byte)
func buildMultiMSGBodyRich(nodes []wire.NodeIDValue) []byte {
	buf := make([]byte, 16) // SCId + TokenId + SeqNo + ReqId

	// TypeID prefix (FourByte NodeId for WriteRequest).
	buf = append(buf, byte(wire.NodeIDFourByte), 0x00)
	var u16 [2]byte
	binary.LittleEndian.PutUint16(u16[:], wire.TypeIDWriteRequest)
	buf = append(buf, u16[:]...)

	// RequestHeader (same fixed-size minimal form as buildMultiMSGBody).
	buf = append(buf, byte(wire.NodeIDTwoByte), 0x00) // AuthToken
	buf = append(buf, make([]byte, 8)...)             // Timestamp
	buf = append(buf, make([]byte, 4)...)             // RequestHandle
	buf = append(buf, make([]byte, 4)...)             // ReturnDiag
	buf = append(buf, 0xFF, 0xFF, 0xFF, 0xFF)         // AuditEntryId null
	buf = append(buf, make([]byte, 4)...)             // TimeoutHint
	buf = append(buf, byte(wire.NodeIDTwoByte), 0x00) // AdditionalHeader NodeId
	buf = append(buf, 0x00)                           // ExtensionObject encoding=0

	// NodesToWrite array length.
	var u32 [4]byte
	binary.LittleEndian.PutUint32(u32[:], uint32(len(nodes)&0xFFFFFFFF)) // #nosec G115 -- test-bounded slice length
	buf = append(buf, u32[:]...)

	for _, n := range nodes {
		buf = append(buf, encodeNodeID(n)...)
		// AttributeId (u32 = 13).
		binary.LittleEndian.PutUint32(u32[:], 13)
		buf = append(buf, u32[:]...)
		// IndexRange null.
		buf = append(buf, 0xFF, 0xFF, 0xFF, 0xFF)
		// DataValue mask = 0.
		buf = append(buf, 0x00)
	}
	return buf
}

// encodeNodeID encodes a rich NodeIDValue in its on-wire form.
// This is the test-only inverse of wire.parseNodeIDRich.
func encodeNodeID(v wire.NodeIDValue) []byte {
	var u16 [2]byte
	var u32 [4]byte
	switch v.Kind {
	case wire.NodeIDKindNumeric:
		// FourByte encoding for the test: enc + ns + u16 id.
		out := []byte{byte(wire.NodeIDFourByte), byte(v.Namespace & 0xFF)}
		binary.LittleEndian.PutUint16(u16[:], uint16(v.Numeric&0xFFFF))
		return append(out, u16[:]...)
	case wire.NodeIDKindString:
		out := []byte{byte(wire.NodeIDString)}
		binary.LittleEndian.PutUint16(u16[:], v.Namespace)
		out = append(out, u16[:]...)
		binary.LittleEndian.PutUint32(u32[:], uint32(len(v.String)&0xFFFFFFFF)) // #nosec G115 -- test-bounded
		out = append(out, u32[:]...)
		return append(out, []byte(v.String)...)
	case wire.NodeIDKindGUID:
		out := []byte{byte(wire.NodeIDGuid)}
		binary.LittleEndian.PutUint16(u16[:], v.Namespace)
		out = append(out, u16[:]...)
		return append(out, v.GUID[:]...)
	case wire.NodeIDKindByteString:
		out := []byte{byte(wire.NodeIDByteString)}
		binary.LittleEndian.PutUint16(u16[:], v.Namespace)
		out = append(out, u16[:]...)
		binary.LittleEndian.PutUint32(u32[:], uint32(len(v.Bytes)&0xFFFFFFFF)) // #nosec G115 -- test-bounded
		out = append(out, u32[:]...)
		return append(out, v.Bytes...)
	}
	panic("unsupported NodeIDKind in test encoder")
}
