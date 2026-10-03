package wire

import (
	"encoding/hex"
	"testing"
)

// Real OPC UA MSG chunks (byte for byte) from CISA cisagov/icsnpp-opcua-binary
// captures of the open62541 stack: a BrowseResponse (service 530) from
// open62541_browse_request_with_results.pcap, and ReadResponses (service 634)
// from the same browse capture (Int32 attribute reads) and from
// open62541_read_service_test_data.pcap (a String/DiagnosticInfo value).
// ParseBrowseResponse / ParseReadResponse take the MSG body, i.e. the chunk
// after its 8-byte UA-TCP header, so each test slices [8:]. This lifts the
// "spec-grounded, not real-capture-validated" caveat for the two codecs the
// writeable-tag walk relies on.

const realBrowseResponse530 = "4d5347462802000008000000080000000600000006000000010012024ca228493f8bd801060000000000000000ffffffff0000000100000000000000ffffffff09000000002d010100d02200001000000054696d655a6f6e65446174615479706503000000001000000054696d655a6f6e654461746154797065400000000000002d010100770300000d0000004555496e666f726d6174696f6e03000000000d0000004555496e666f726d6174696f6e400000000000002d010100740300000500000052616e676503000000000500000052616e6765400000000000002d0101005e0300001400000053657276657253746174757344617461547970650300000000140000005365727665725374617475734461746154797065400000000000002d010100aa1d00000d000000456e756d56616c75655479706503000000000d000000456e756d56616c756554797065400000000000002d01010058010000190000005369676e6564536f66747761726543657274696669636174650300000000190000005369676e6564536f6674776172654365727469666963617465400000000000002d01010052010000090000004275696c64496e666f0300000000090000004275696c64496e666f400000000000002d0101002801000008000000417267756d656e74030000000008000000417267756d656e74400000000000002d010100d431000005000000556e696f6e030000000005000000556e696f6e400000000000ffffffff"

// ReadResponse carrying a single Int32 attribute (the integer path the walk
// uses for NodeClass / UserAccessLevel).
const realReadResponseInt32 = "4d534746420000000800000008000000140000001400000001007a02eaab30493f8bd801140000000000000000ffffffff00000001000000010601000000ffffffff"

// ReadResponse carrying a String value (DiagnosticInfo text); the walk's
// integer-only decoder fail-closes on it by design.
const realReadResponseString = "4d534746160100000100000001000000540000005400000001007a02ba56024ba2d9d801550000000000000000ffffffff000000010000000519703d00000041204e657374656420446961676e6f73746963496e666f207661726961626c652077697468206164646974696f6e616c20696e666f726d6174696f6e2e00000000703c000000496e6e657220446961676e6f73746963496e666f2031207661726961626c652077697468206164646974696f6e616c20696e666f726d6174696f6e2e00001581303c000000496e6e657220446961676e6f73746963496e666f2032207661726961626c652077697468206164646974696f6e616c20696e666f726d6174696f6e2e00009600ba56024ba2d9d801ffffffff"

func TestParseBrowseResponse_RealCapture(t *testing.T) {
	raw, err := hex.DecodeString(realBrowseResponse530)
	if err != nil {
		t.Fatal(err)
	}
	refs, ok := ParseBrowseResponse(raw[8:])
	if !ok {
		t.Fatal("ParseBrowseResponse returned ok=false on a real BrowseResponse")
	}
	if len(refs) != 9 {
		t.Fatalf("got %d refs, want 9", len(refs))
	}
	// First reference in the capture: BrowseName "TimeZoneDataType",
	// NodeClass DataType (64).
	if refs[0].BrowseName != "TimeZoneDataType" {
		t.Errorf("refs[0].BrowseName=%q, want TimeZoneDataType", refs[0].BrowseName)
	}
	if refs[0].NodeClass != 64 {
		t.Errorf("refs[0].NodeClass=%d, want 64 (DataType)", refs[0].NodeClass)
	}
	// Every ref carries a non-empty NodeId and BrowseName.
	for i, r := range refs {
		if len(r.NodeID) == 0 || r.BrowseName == "" {
			t.Errorf("refs[%d] incomplete: %+v", i, r)
		}
	}
}

func TestParseReadResponse_RealCapture(t *testing.T) {
	// Integer path: a real Int32 attribute read parses to its value.
	raw, err := hex.DecodeString(realReadResponseInt32)
	if err != nil {
		t.Fatal(err)
	}
	vals, ok := ParseReadResponse(raw[8:])
	if !ok {
		t.Fatal("ParseReadResponse returned ok=false on a real Int32 ReadResponse")
	}
	if len(vals) != 1 {
		t.Fatalf("got %d values, want 1", len(vals))
	}
	if !vals[0].HasValue || vals[0].BuiltinType != builtinInt32 || vals[0].UintValue != 1 {
		t.Errorf("value = %+v, want HasValue int32=1", vals[0])
	}

	// Non-integer path: a real String/DiagnosticInfo value fail-closes by
	// design (the walk only decodes integer attributes), without a panic.
	raw, err = hex.DecodeString(realReadResponseString)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ParseReadResponse(raw[8:]); ok {
		t.Error("ParseReadResponse should fail-close on a non-integer (String) value")
	}
}
