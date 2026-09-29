package opcua_test

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"local/elsereno/internal/protocols/opcua"
	"local/elsereno/internal/protocols/opcua/wire"
)

// --- response builders for the walk fake server (spec-crafted) ---

func le16(v uint16) []byte {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, v)
	return b
}

func uaStr(s string) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(len(s))) // #nosec G115 -- test strings are short
	return append(b, s...)
}

// respHeaderGood is a minimal Good ResponseHeader (matches the wire
// package's cur.responseHeader()).
func respHeaderGood() []byte {
	var b []byte
	b = append(b, make([]byte, 8)...) // timestamp
	b = append(b, le32(1)...)         // requestHandle
	b = append(b, le32(0)...)         // serviceResult = Good
	b = append(b, 0x00)               // serviceDiagnostics (empty)
	b = append(b, le32(0)...)         // stringTable count 0
	b = append(b, 0x00, 0x00, 0x00)   // additionalHeader null ExtObj
	return b
}

// refSpec is one child reference to encode into a BrowseResponse.
type refSpec struct {
	refType   uint16
	nodeID    uint16
	name      string
	nodeClass uint32
	typeDef   uint16
}

func buildBrowseResp(refs []refSpec) []byte {
	var b []byte
	b = append(b, make([]byte, 16)...)         // symmetric header prefix
	b = append(b, wire.FourByteNodeID(532)...) // TypeId BrowseResponse
	b = append(b, respHeaderGood()...)
	b = append(b, le32(1)...)                 // results: array count 1
	b = append(b, le32(0)...)                 // BrowseResult.statusCode Good
	b = append(b, le32(0xFFFFFFFF)...)        // continuationPoint: null ByteString
	b = append(b, le32(uint32(len(refs)))...) // #nosec G115 -- test-bounded
	for _, r := range refs {
		b = append(b, wire.FourByteNodeID(r.refType)...) // referenceTypeId
		b = append(b, 0x01)                              // isForward
		b = append(b, wire.FourByteNodeID(r.nodeID)...)  // nodeId (ExpandedNodeId, no flags)
		b = append(b, le16(0)...)                        // browseName QualifiedName ns
		b = append(b, uaStr(r.name)...)                  // browseName name
		b = append(b, 0x02)                              // displayName LocalizedText mask
		b = append(b, uaStr(r.name)...)                  // displayName text
		b = append(b, le32(r.nodeClass)...)              // nodeClass
		b = append(b, wire.FourByteNodeID(r.typeDef)...) // typeDefinition
	}
	b = append(b, le32(0)...) // diagnosticInfos count 0
	return frameMSG(b)
}

func buildReadUALResp(vals ...byte) []byte {
	var b []byte
	b = append(b, make([]byte, 16)...)
	b = append(b, wire.FourByteNodeID(634)...) // TypeId ReadResponse
	b = append(b, respHeaderGood()...)
	b = append(b, le32(uint32(len(vals)))...) // #nosec G115 -- test-bounded
	for _, v := range vals {
		b = append(b, 0x01) // DataValue EncodingMask: Value present
		b = append(b, 0x03) // Variant encoding mask: Byte scalar
		b = append(b, v)    // UserAccessLevel value
	}
	b = append(b, le32(0)...) // diagnosticInfos count 0
	return frameMSG(b)
}

// TestProbeWriteableNodes drives the full walk over net.Pipe: handshake ->
// Browse(i=85) [Variable Setpoint + Object SubFolder] -> Read(UAL=0x03) ->
// descend Browse(SubFolder) [Variable Readback] -> Read(UAL=0x01). Only
// Setpoint (CurrentWrite) is flagged.
func TestProbeWriteableNodes(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() { _ = clientConn.Close(); _ = serverConn.Close() })

	responses := [][]byte{
		buildACK(),
		mustHex(t, realOPNResponse),
		buildGetEndpointsResp(t),
		buildCreateSessionResp(),
		mustHex(t, realActivateSessionResp),
		buildBrowseResp([]refSpec{
			{refType: 47, nodeID: 42, name: "Setpoint", nodeClass: 2, typeDef: 63},  // Variable, writeable
			{refType: 35, nodeID: 99, name: "SubFolder", nodeClass: 1, typeDef: 61}, // Object -> descend
		}),
		buildReadUALResp(0x03), // Setpoint: CurrentRead|CurrentWrite
		buildBrowseResp([]refSpec{
			{refType: 47, nodeID: 43, name: "Readback", nodeClass: 2, typeDef: 63}, // Variable, read-only
		}),
		buildReadUALResp(0x01), // Readback: CurrentRead only
	}
	go func() {
		for _, resp := range responses {
			serverReadMessage(t, serverConn)
			if _, err := serverConn.Write(resp); err != nil {
				return
			}
		}
	}()

	_ = clientConn.SetDeadline(time.Now().Add(2 * time.Second))
	res, err := opcua.ProbeWriteableNodes(context.Background(), clientConn, "opc.tcp://plc.test:4840", 100)
	if err != nil {
		t.Fatalf("ProbeWriteableNodes: %v", err)
	}
	if !res.SessionOpened {
		t.Fatal("SessionOpened = false")
	}
	if res.FoldersBrowsed != 2 {
		t.Errorf("FoldersBrowsed = %d, want 2 (i=85 + SubFolder)", res.FoldersBrowsed)
	}
	if res.VariablesRead != 2 {
		t.Errorf("VariablesRead = %d, want 2", res.VariablesRead)
	}
	if len(res.Writeable) != 1 {
		t.Fatalf("Writeable count = %d, want 1: %+v", len(res.Writeable), res.Writeable)
	}
	w := res.Writeable[0]
	if w.NodeID != "i=42" || w.BrowseName != "Setpoint" || w.UserAccessLevel != 0x03 {
		t.Errorf("Writeable[0] = %+v, want {i=42 Setpoint 0x03}", w)
	}
}

// TestProbeWriteableNodes_NotExposed: when the session never opens (server
// answers HELLO with ERR), the walk returns without browsing anything.
func TestProbeWriteableNodes_NotExposed(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() { _ = clientConn.Close(); _ = serverConn.Close() })
	go func() {
		serverReadMessage(t, serverConn)
		errMsg := []byte{'E', 'R', 'R', 'F'}
		errMsg = append(errMsg, le32(12)...)
		errMsg = append(errMsg, make([]byte, 4)...)
		_, _ = serverConn.Write(errMsg)
	}()
	_ = clientConn.SetDeadline(time.Now().Add(2 * time.Second))
	res, err := opcua.ProbeWriteableNodes(context.Background(), clientConn, "opc.tcp://x:4840", 100)
	if err != nil {
		t.Fatalf("ProbeWriteableNodes: %v", err)
	}
	if res.SessionOpened || res.FoldersBrowsed != 0 || len(res.Writeable) != 0 {
		t.Fatalf("expected an unexposed server to walk nothing: %+v", res)
	}
}
