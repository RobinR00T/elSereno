package wire

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// le32 / le16 are little-endian helpers for hand-building spec fixtures.
func le32(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

// responseHeaderFixture returns a minimal, well-formed ResponseHeader:
// zero timestamp + handle, Good serviceResult, empty diagnostics/strings,
// null additionalHeader. Matches what cur.responseHeader() walks.
func responseHeaderFixture() []byte {
	var b []byte
	b = append(b, make([]byte, 8)...)  // timestamp DateTime
	b = append(b, le32(1)...)          // requestHandle
	b = append(b, le32(StatusGood)...) // serviceResult
	b = append(b, 0x00)                // serviceDiagnostics: DiagnosticInfo mask 0 (empty)
	b = append(b, le32(0)...)          // stringTable: array count 0
	b = append(b, 0x00, 0x00, 0x00)    // additionalHeader: null NodeId (TwoByte 0) + encoding 0x00
	return b
}

// msgPrefixAndType returns a 16-byte symmetric header + a FourByte
// message TypeId, the framing every service-response body starts with.
func msgPrefixAndType(typeID uint16) []byte {
	b := make([]byte, 16) // SecureChannelId + TokenId + SequenceNumber + RequestId
	b = putFourByteNodeID(b, typeID)
	return b
}

func TestFourByteNodeID(t *testing.T) {
	got := FourByteNodeID(85) // ObjectsFolder i=85
	want := []byte{0x01, 0x00, 0x55, 0x00}
	if !bytes.Equal(got, want) {
		t.Fatalf("FourByteNodeID(85) = % x, want % x", got, want)
	}
}

func TestEncodeReadRequestTCP_Structure(t *testing.T) {
	targets := []ReadTarget{
		{NodeID: FourByteNodeID(85), AttributeID: AttrNodeClass},
		{NodeID: FourByteNodeID(85), AttributeID: AttrUserAccessLevel},
	}
	req := EncodeReadRequestTCP(1, 2, 5, 5, nullAuthToken, targets)

	h, err := ParseHeader(req[:HeaderSize])
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	if h.Type != MessageMessage {
		t.Fatalf("message type = %q, want MSG", h.Type)
	}
	if int(h.Length) != len(req) {
		t.Fatalf("header length %d != actual %d", h.Length, len(req))
	}
	id, ok := ServiceTypeID(req[HeaderSize:])
	if !ok || id != TypeIDReadRequest {
		t.Fatalf("ServiceTypeID = %d ok=%v, want %d", id, ok, TypeIDReadRequest)
	}
	// The attribute IDs must appear as LE u32 in the request body.
	if !bytes.Contains(req, le32(AttrUserAccessLevel)) {
		t.Errorf("UserAccessLevel attribute id (18) not found in request")
	}
	if !bytes.Contains(req, le32(AttrNodeClass)) {
		t.Errorf("NodeClass attribute id (2) not found in request")
	}
}

// TestParseReadResponse decodes a spec-crafted ReadResponse carrying two
// DataValues: NodeClass=Variable(2) as an Int32 scalar, and
// UserAccessLevel=CurrentRead|CurrentWrite(0x03) as a Byte scalar with a
// Good StatusCode. See read.go's validation note: no real Read capture
// exists for this project, so the fixture is built to Part 6 §5.2.
func TestParseReadResponse(t *testing.T) {
	body := msgPrefixAndType(634) // ReadResponse_Encoding_DefaultBinary i=634
	body = append(body, responseHeaderFixture()...)
	body = append(body, le32(2)...) // results: array count 2

	// DataValue 1: NodeClass, Value-only (mask 0x01), Variant Int32 = 2.
	body = append(body, 0x01)         // DataValue EncodingMask: Value present
	body = append(body, builtinInt32) // Variant encoding mask: Int32 scalar
	body = append(body, le32(NodeClassVariable)...)

	// DataValue 2: UserAccessLevel, Value+Status (mask 0x03), Byte 0x03.
	body = append(body, 0x03)                // DataValue EncodingMask: Value + StatusCode
	body = append(body, builtinByte)         // Variant encoding mask: Byte scalar
	body = append(body, 0x03)                // value: CurrentRead|CurrentWrite
	body = append(body, le32(StatusGood)...) // StatusCode

	body = append(body, le32(0)...) // diagnosticInfos: array count 0 (trailing, ignored)

	results, ok := ParseReadResponse(body)
	if !ok {
		t.Fatalf("ParseReadResponse ok=false")
	}
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
	if !results[0].HasValue || results[0].BuiltinType != builtinInt32 || results[0].UintValue != uint64(NodeClassVariable) {
		t.Errorf("NodeClass result = %+v, want Int32 value 2", results[0])
	}
	if !results[1].HasValue || results[1].BuiltinType != builtinByte || results[1].UintValue != 0x03 {
		t.Errorf("UserAccessLevel result = %+v, want Byte value 0x03", results[1])
	}
	if results[1].Status != StatusGood {
		t.Errorf("UserAccessLevel status = 0x%08x, want Good", results[1].Status)
	}
	// The finding logic: NodeClass==Variable AND UserAccessLevel has
	// CurrentWrite -> writeable by the (anonymous) user.
	writeable := results[0].UintValue == uint64(NodeClassVariable) &&
		results[1].UintValue&uint64(AccessLevelCurrentWrite) != 0
	if !writeable {
		t.Errorf("expected node to be flagged writeable-by-anonymous")
	}
}

// TestParseReadResponse_Truncated fails closed on a body cut mid-result.
func TestParseReadResponse_Truncated(t *testing.T) {
	body := msgPrefixAndType(634)
	body = append(body, responseHeaderFixture()...)
	body = append(body, le32(2)...)               // claims 2 results ...
	body = append(body, 0x01, builtinInt32, 0x02) // ... but only 1 partial
	if _, ok := ParseReadResponse(body); ok {
		t.Fatalf("expected ok=false on truncated ReadResponse")
	}
}

// TestParseReadResponse_ArrayValueFailsClosed: an array Variant (not
// expected for a scalar attribute) must fail the parse, not be guessed.
func TestParseReadResponse_ArrayValueFailsClosed(t *testing.T) {
	body := msgPrefixAndType(634)
	body = append(body, responseHeaderFixture()...)
	body = append(body, le32(1)...)
	body = append(body, 0x01)             // Value present
	body = append(body, builtinByte|0x80) // array flag set
	body = append(body, le32(1)...)       // array len 1
	body = append(body, 0x03)             // one byte
	if _, ok := ParseReadResponse(body); ok {
		t.Fatalf("expected ok=false on array-valued attribute")
	}
}
