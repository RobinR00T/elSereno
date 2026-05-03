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

// ---- Hash ladder: rich chunk-6 variant degrades ---------

func TestAllowlistHashWithCallMethods_EmptyMatchesChunk3(t *testing.T) {
	svcs := []opwrite.AllowedService{{TypeID: wire.TypeIDCallRequest}}
	canon := []opwrite.AllowedCanonicalNodeID{"ns=2;s=Temperature"}
	h3 := opwrite.AllowlistHashWithRichNodeIDs("host:4840", svcs, nil, canon)
	h6 := opwrite.AllowlistHashWithCallMethods("host:4840", svcs, nil, canon, nil)
	if !bytes.Equal(h3[:], h6[:]) {
		t.Fatalf("chunk-6 with empty call-methods differs from chunk-3: %x vs %x", h6, h3)
	}
}

func TestAllowlistHashWithCallMethods_EmptyAllMatchesV12(t *testing.T) {
	svcs := []opwrite.AllowedService{{TypeID: wire.TypeIDCallRequest}}
	h12 := opwrite.AllowlistHash("host:4840", svcs)
	h6 := opwrite.AllowlistHashWithCallMethods("host:4840", svcs, nil, nil, nil)
	if !bytes.Equal(h12[:], h6[:]) {
		t.Fatalf("chunk-6 with all-empty differs from v1.2: %x vs %x", h6, h12)
	}
}

func TestAllowlistHashWithCallMethods_NonEmptyChangesHash(t *testing.T) {
	svcs := []opwrite.AllowedService{{TypeID: wire.TypeIDCallRequest}}
	call := []opwrite.AllowedCallMethod{{ObjectID: "ns=2;i=100", MethodID: "ns=2;i=101"}}
	h3 := opwrite.AllowlistHashWithRichNodeIDs("host:4840", svcs, nil, nil)
	h6 := opwrite.AllowlistHashWithCallMethods("host:4840", svcs, nil, nil, call)
	if bytes.Equal(h3[:], h6[:]) {
		t.Fatal("chunk-6 with non-empty call-methods must differ from chunk-3")
	}
}

func TestAllowlistHashWithCallMethods_OrderInsensitive(t *testing.T) {
	svcs := []opwrite.AllowedService{{TypeID: wire.TypeIDCallRequest}}
	a := []opwrite.AllowedCallMethod{
		{ObjectID: "ns=2;i=100", MethodID: "ns=2;i=101"},
		{ObjectID: "ns=3;s=DeviceFolder", MethodID: "ns=3;s=Restart"},
	}
	b := []opwrite.AllowedCallMethod{
		{ObjectID: "ns=3;s=DeviceFolder", MethodID: "ns=3;s=Restart"},
		{ObjectID: "ns=2;i=100", MethodID: "ns=2;i=101"},
	}
	h1 := opwrite.AllowlistHashWithCallMethods("host:4840", svcs, nil, nil, a)
	h2 := opwrite.AllowlistHashWithCallMethods("host:4840", svcs, nil, nil, b)
	if !bytes.Equal(h1[:], h2[:]) {
		t.Fatal("hash depends on call-method input order")
	}
}

// ---- Wire parser: CallRequestAllMethods ----------------

func TestCallRequestAllMethods_SingleMethod(t *testing.T) {
	body := buildCallMSGBody([]wire.CallMethod{
		{
			ObjectID: wire.NodeIDValue{Namespace: 2, Kind: wire.NodeIDKindNumeric, Numeric: 100},
			MethodID: wire.NodeIDValue{Namespace: 2, Kind: wire.NodeIDKindNumeric, Numeric: 101},
		},
	})
	methods, ok := wire.CallRequestAllMethods(body)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if len(methods) != 1 {
		t.Fatalf("len=%d, want 1", len(methods))
	}
	if methods[0].ObjectID.Canonical() != "ns=2;i=100" || methods[0].MethodID.Canonical() != "ns=2;i=101" {
		t.Errorf("methods[0] = %+v", methods[0])
	}
}

func TestCallRequestAllMethods_MultipleWithMixedEncodings(t *testing.T) {
	body := buildCallMSGBody([]wire.CallMethod{
		{
			ObjectID: wire.NodeIDValue{Namespace: 2, Kind: wire.NodeIDKindNumeric, Numeric: 100},
			MethodID: wire.NodeIDValue{Namespace: 2, Kind: wire.NodeIDKindNumeric, Numeric: 101},
		},
		{
			ObjectID: wire.NodeIDValue{Namespace: 3, Kind: wire.NodeIDKindString, String: "DeviceFolder"},
			MethodID: wire.NodeIDValue{Namespace: 3, Kind: wire.NodeIDKindString, String: "Restart"},
		},
	})
	methods, ok := wire.CallRequestAllMethods(body)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if len(methods) != 2 {
		t.Fatalf("len=%d, want 2", len(methods))
	}
	if methods[1].ObjectID.Canonical() != "ns=3;s=DeviceFolder" {
		t.Errorf("methods[1].Object = %q", methods[1].ObjectID.Canonical())
	}
}

func TestCallRequestAllMethods_EmptyArrayFails(t *testing.T) {
	body := buildCallMSGBody(nil)
	_, ok := wire.CallRequestAllMethods(body)
	if ok {
		t.Fatal("empty MethodsToCall should return ok=false")
	}
}

func TestCallRequestAllMethods_TruncatedFails(t *testing.T) {
	body := buildCallMSGBody([]wire.CallMethod{
		{
			ObjectID: wire.NodeIDValue{Namespace: 2, Kind: wire.NodeIDKindNumeric, Numeric: 100},
			MethodID: wire.NodeIDValue{Namespace: 2, Kind: wire.NodeIDKindNumeric, Numeric: 101},
		},
	})
	_, ok := wire.CallRequestAllMethods(body[:len(body)-4])
	if ok {
		t.Fatal("truncated body should return ok=false")
	}
}

// ---- E2E gate tests --------------------------------------

// driveCallMethodSession authorises a handler with CallRequest
// service allowed + a per-CallMethod allowlist.
func driveCallMethodSession(t *testing.T, calls []opwrite.AllowedCallMethod) (net.Conn, *safeBuffer) {
	t.Helper()
	target := "plc.test:4840"
	svcs := []opwrite.AllowedService{{TypeID: wire.TypeIDCallRequest}}
	h := &opwrite.WriteGatedHandler{
		Target:             target,
		Allowed:            svcs,
		AllowedCallMethods: calls,
		Deriver:            &fakeDeriverNode{key: []byte(testDeriverKeyNode)},
		Auditor:            &fakeAuditorNode{},
	}
	mut := opwrite.SessionMutationWithCallMethods(target, svcs, nil, nil, calls)
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

func TestGateCallMethod_AllowedPasses(t *testing.T) {
	calls := []opwrite.AllowedCallMethod{
		{ObjectID: "ns=2;i=100", MethodID: "ns=2;i=101"},
	}
	client, upstreamBuf := driveCallMethodSession(t, calls)

	body := buildCallMSGBody([]wire.CallMethod{
		{
			ObjectID: wire.NodeIDValue{Namespace: 2, Kind: wire.NodeIDKindNumeric, Numeric: 100},
			MethodID: wire.NodeIDValue{Namespace: 2, Kind: wire.NodeIDKindNumeric, Numeric: 101},
		},
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
		t.Fatal("upstream saw nothing for allowed CallMethod")
	}
}

func TestGateCallMethod_OneForbiddenRefuses(t *testing.T) {
	calls := []opwrite.AllowedCallMethod{
		{ObjectID: "ns=2;i=100", MethodID: "ns=2;i=101"},
	}
	client, upstreamBuf := driveCallMethodSession(t, calls)

	// Allowed (100,101) first, then FORBIDDEN (100,999) — whole
	// request must refuse.
	body := buildCallMSGBody([]wire.CallMethod{
		{
			ObjectID: wire.NodeIDValue{Namespace: 2, Kind: wire.NodeIDKindNumeric, Numeric: 100},
			MethodID: wire.NodeIDValue{Namespace: 2, Kind: wire.NodeIDKindNumeric, Numeric: 101},
		},
		{
			ObjectID: wire.NodeIDValue{Namespace: 2, Kind: wire.NodeIDKindNumeric, Numeric: 100},
			MethodID: wire.NodeIDValue{Namespace: 2, Kind: wire.NodeIDKindNumeric, Numeric: 999},
		},
	})
	_, _ = client.Write(wrapMultiMSG(body))

	_ = client.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	rbuf := make([]byte, 2048)
	n, err := client.Read(rbuf)
	if err != nil {
		t.Fatalf("read fault: %v", err)
	}
	if n == 0 || !bytes.HasPrefix(rbuf[:n], []byte("MSG")) {
		t.Fatalf("expected MSG (ServiceFault) refusal, got % x", rbuf[:8])
	}
	time.Sleep(50 * time.Millisecond)
	if upstreamBuf.Len() != 0 {
		t.Fatalf("upstream saw %d bytes for forbidden CallMethod batch", upstreamBuf.Len())
	}
}

func TestGateCallMethod_StringNodeMatches(t *testing.T) {
	calls := []opwrite.AllowedCallMethod{
		{ObjectID: "ns=3;s=DeviceFolder", MethodID: "ns=3;s=Restart"},
	}
	client, upstreamBuf := driveCallMethodSession(t, calls)

	body := buildCallMSGBody([]wire.CallMethod{
		{
			ObjectID: wire.NodeIDValue{Namespace: 3, Kind: wire.NodeIDKindString, String: "DeviceFolder"},
			MethodID: wire.NodeIDValue{Namespace: 3, Kind: wire.NodeIDKindString, String: "Restart"},
		},
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
		t.Fatal("upstream saw nothing for allowed string-NodeId CallMethod")
	}
}

// ---- Helpers: build a CallRequest MSG body -------------

// buildCallMSGBody crafts a CallRequest MSG body carrying N
// CallMethodRequest entries. Each entry:
//
//	ObjectID (variable)
//	MethodID (variable)
//	InputArguments: Variant[]  — always null for simplicity
//	                 (-1 i32 length prefix, 4 bytes)
func buildCallMSGBody(methods []wire.CallMethod) []byte {
	buf := make([]byte, 16) // SCId + TokenId + SeqNo + ReqId

	// TypeID prefix (FourByte NodeId for CallRequest = 704).
	buf = append(buf, byte(wire.NodeIDFourByte), 0x00)
	var u16 [2]byte
	binary.LittleEndian.PutUint16(u16[:], wire.TypeIDCallRequest)
	buf = append(buf, u16[:]...)

	// RequestHeader (same minimal shape as write-request tests).
	buf = append(buf, byte(wire.NodeIDTwoByte), 0x00) // AuthToken
	buf = append(buf, make([]byte, 8)...)             // Timestamp
	buf = append(buf, make([]byte, 4)...)             // RequestHandle
	buf = append(buf, make([]byte, 4)...)             // ReturnDiag
	buf = append(buf, 0xFF, 0xFF, 0xFF, 0xFF)         // AuditEntryId null
	buf = append(buf, make([]byte, 4)...)             // TimeoutHint
	buf = append(buf, byte(wire.NodeIDTwoByte), 0x00) // AdditionalHeader NodeId
	buf = append(buf, 0x00)                           // ExtensionObject encoding=0

	// MethodsToCall array length.
	var u32 [4]byte
	binary.LittleEndian.PutUint32(u32[:], uint32(len(methods)&0xFFFFFFFF)) // #nosec G115 -- test-bounded
	buf = append(buf, u32[:]...)

	for _, m := range methods {
		buf = append(buf, encodeNodeID(m.ObjectID)...)
		buf = append(buf, encodeNodeID(m.MethodID)...)
		// InputArguments: null array (-1 i32 length).
		buf = append(buf, 0xFF, 0xFF, 0xFF, 0xFF)
	}
	return buf
}
