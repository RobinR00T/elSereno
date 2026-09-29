package wire

import (
	"bytes"
	"testing"
)

// --- test encoders for hand-building spec fixtures ---

func tStr(s string) []byte {
	b := le32(uint32(len(s))) // #nosec G115 -- test strings are short
	return append(b, []byte(s)...)
}

func tQualifiedName(name string) []byte {
	return append([]byte{0x00, 0x00}, tStr(name)...) // ns u16 + name String
}

func tLocalizedText(text string) []byte {
	return append([]byte{0x02}, tStr(text)...) // mask 0x02 (text only) + String
}

func tReferenceDescription(refType uint16, nodeID uint16, name string, nodeClass uint32, typeDef uint16) []byte {
	var b []byte
	b = append(b, FourByteNodeID(refType)...) // referenceTypeId
	b = append(b, 0x01)                       // isForward
	b = append(b, FourByteNodeID(nodeID)...)  // nodeId (ExpandedNodeId, no flags)
	b = append(b, tQualifiedName(name)...)
	b = append(b, tLocalizedText(name)...)
	b = append(b, le32(nodeClass)...)         // nodeClass (Int32 enum)
	b = append(b, FourByteNodeID(typeDef)...) // typeDefinition
	return b
}

func TestEncodeBrowseRequestTCP_Structure(t *testing.T) {
	req := EncodeBrowseRequestTCP(1, 2, 6, 6, nullAuthToken, FourByteNodeID(85), 0)

	h, err := ParseHeader(req[:HeaderSize])
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	if h.Type != MessageMessage {
		t.Fatalf("message type = %q, want MSG", h.Type)
	}
	id, ok := ServiceTypeID(req[HeaderSize:])
	if !ok || id != TypeIDBrowseRequest {
		t.Fatalf("ServiceTypeID = %d ok=%v, want %d", id, ok, TypeIDBrowseRequest)
	}
	if !bytes.Contains(req, FourByteNodeID(85)) {
		t.Errorf("start node i=85 not found in BrowseRequest")
	}
	if !bytes.Contains(req, FourByteNodeID(referenceTypeHierarchical)) {
		t.Errorf("HierarchicalReferences i=33 not found in BrowseRequest")
	}
}

// TestParseBrowseResponse decodes a spec-crafted BrowseResponse: one
// BrowseResult with two references (a Variable and an Object). See
// browse.go's validation note.
func TestParseBrowseResponse(t *testing.T) {
	body := msgPrefixAndType(532) // BrowseResponse_Encoding_DefaultBinary i=532
	body = append(body, responseHeaderFixture()...)
	body = append(body, le32(1)...) // results: array count 1

	// BrowseResult 1.
	body = append(body, le32(StatusGood)...) // statusCode
	body = append(body, le32(0xFFFFFFFF)...) // continuationPoint: null ByteString
	body = append(body, le32(2)...)          // references: array count 2
	body = append(body, tReferenceDescription(47, 42, "Temperature", NodeClassVariable, 63)...)
	body = append(body, tReferenceDescription(35, 1000, "DeviceSet", 1 /*Object*/, 0)...)

	body = append(body, le32(0)...) // diagnosticInfos: array count 0 (trailing)

	refs, ok := ParseBrowseResponse(body)
	if !ok {
		t.Fatalf("ParseBrowseResponse ok=false")
	}
	if len(refs) != 2 {
		t.Fatalf("got %d refs, want 2", len(refs))
	}
	if refs[0].NodeClass != NodeClassVariable || refs[0].BrowseName != "Temperature" ||
		!bytes.Equal(refs[0].NodeID, FourByteNodeID(42)) {
		t.Errorf("ref[0] = %+v, want Variable Temperature i=42", refs[0])
	}
	if refs[1].NodeClass != 1 || refs[1].BrowseName != "DeviceSet" ||
		!bytes.Equal(refs[1].NodeID, FourByteNodeID(1000)) {
		t.Errorf("ref[1] = %+v, want Object DeviceSet i=1000", refs[1])
	}
}

// TestExpandedNodeID_StripsFlags: an ExpandedNodeId carrying a
// NamespaceUri (flag 0x80) must yield a plain NodeId with the flag
// cleared, and the NamespaceUri must be consumed (cursor not failed).
func TestExpandedNodeID_StripsFlags(t *testing.T) {
	var b []byte
	b = append(b, 0x81, 0x00, 0x07, 0x00) // FourByte(0x01) | NamespaceUri(0x80), ns 0, id 7
	b = append(b, tStr("urn:x")...)       // NamespaceUri String
	b = append(b, 0xAB)                   // sentinel: must remain unread by nodeId part
	c := &cur{b: b}
	got := c.expandedNodeID()
	if c.fail() {
		t.Fatalf("cursor failed decoding ExpandedNodeId with NamespaceUri")
	}
	if !bytes.Equal(got, FourByteNodeID(7)) {
		t.Fatalf("got % x, want plain NodeId % x", got, FourByteNodeID(7))
	}
	if c.off != len(b)-1 { // consumed everything but the sentinel
		t.Fatalf("cursor at %d, want %d (NamespaceUri not fully consumed)", c.off, len(b)-1)
	}
}

func TestParseBrowseResponse_Truncated(t *testing.T) {
	body := msgPrefixAndType(532)
	body = append(body, responseHeaderFixture()...)
	body = append(body, le32(1)...)            // 1 result
	body = append(body, le32(StatusGood)...)   // statusCode
	body = append(body, le32(0xFFFFFFFF)...)   // null continuationPoint
	body = append(body, le32(5)...)            // claims 5 references ...
	body = append(body, FourByteNodeID(47)...) // ... but cut mid-first-ref
	if _, ok := ParseBrowseResponse(body); ok {
		t.Fatalf("expected ok=false on truncated BrowseResponse")
	}
}
