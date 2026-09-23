//go:build offensive

package opcuahttps_test

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"local/elsereno/internal/protocols/opcua/wire"
	"local/elsereno/offensive/confirm"
	opcua "local/elsereno/offensive/write/opcua"
	uahttps "local/elsereno/offensive/write/opcuahttps"
)

// ---- fakes ----------------------------------------------------

type fakeDeriver struct{ key []byte }

func (f *fakeDeriver) Derive(_ string, out []byte) error {
	copy(out, f.key)
	return nil
}

type fakeAuditor struct {
	mu     sync.Mutex
	events []confirm.AuditEvent
}

func (f *fakeAuditor) Record(_ context.Context, ev confirm.AuditEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, ev)
	return nil
}

const testDeriverKey = "test-key-32-byte-long--------"

type allowlist struct {
	services []opcua.AllowedService
	nodeIDs  []opcua.AllowedNodeID
	canon    []opcua.AllowedCanonicalNodeID
	calls    []opcua.AllowedCallMethod
}

func mintToken(t *testing.T, target string, a allowlist) string {
	t.Helper()
	mut := uahttps.SessionMutation(target, a.services, a.nodeIDs, a.canon, a.calls, 0)
	tok, err := confirm.ExpectedToken(mut, &fakeDeriver{key: []byte(testDeriverKey)})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func newHandler(t *testing.T, target string, a allowlist) *uahttps.WriteGatedHandler {
	t.Helper()
	h := &uahttps.WriteGatedHandler{
		Target:                  target,
		Allowed:                 a.services,
		AllowedNodeIDs:          a.nodeIDs,
		AllowedCanonicalNodeIDs: a.canon,
		AllowedCallMethods:      a.calls,
		Deriver:                 &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor:                 &fakeAuditor{},
		SessionConfirm: confirm.Confirm{
			AcceptsWrites: true,
			ConfirmTarget: target,
			ConfirmToken:  mintToken(t, target, a),
		},
	}
	if err := h.Authorise(context.Background()); err != nil {
		t.Fatal(err)
	}
	return h
}

// upstreamServer is a fake origin that tags every response with
// X-Upstream so a test can tell a forwarded request (reached upstream)
// from a gate refusal (synthesised locally, never reaches upstream).
type upstreamServer struct {
	mu       sync.Mutex
	requests []*http.Request
}

func (u *upstreamServer) run(conn net.Conn) {
	br := bufio.NewReader(conn)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		u.mu.Lock()
		u.requests = append(u.requests, req)
		u.mu.Unlock()
		_, _ = io.Copy(io.Discard, req.Body)
		_ = req.Body.Close()
		_, _ = io.WriteString(conn,
			"HTTP/1.1 200 OK\r\nX-Upstream: yes\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n")
	}
}

func (u *upstreamServer) seen() []*http.Request {
	u.mu.Lock()
	defer u.mu.Unlock()
	out := make([]*http.Request, len(u.requests))
	copy(out, u.requests)
	return out
}

func driveSession(t *testing.T, a allowlist) (net.Conn, *upstreamServer) {
	t.Helper()
	target := "plc.test:4843"
	h := newHandler(t, target, a)

	clientPipe, handlerClientSide := net.Pipe()
	handlerUpstreamSide, originSide := net.Pipe()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = clientPipe.Close()
		_ = handlerClientSide.Close()
		_ = handlerUpstreamSide.Close()
		_ = originSide.Close()
	})

	srv := &upstreamServer{}
	go srv.run(originSide)
	go func() { _ = h.Handle(ctx, handlerClientSide, handlerUpstreamSide) }()
	return clientPipe, srv
}

// response is a snapshot of one HTTP response the gate emitted.
type response struct {
	Code         int
	GateReason   string // X-Elsereno-Gate-Reason header (set on a refusal)
	FromUpstream bool   // X-Upstream header (set only by the fake origin)
	Body         []byte
}

func readResponse(t *testing.T, conn net.Conn) response {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return response{
		Code:         resp.StatusCode,
		GateReason:   resp.Header.Get("X-Elsereno-Gate-Reason"),
		FromUpstream: resp.Header.Get("X-Upstream") == "yes",
		Body:         body,
	}
}

func waitSeen(t *testing.T, srv *upstreamServer) {
	t.Helper()
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if len(srv.seen()) >= 1 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("upstream saw %d requests; wanted >= 1", len(srv.seen()))
}

func mustNotSee(t *testing.T, srv *upstreamServer) {
	t.Helper()
	time.Sleep(50 * time.Millisecond)
	if got := srv.seen(); len(got) != 0 {
		t.Fatalf("upstream saw %d requests; expected 0 (refusal must not forward)", len(got))
	}
}

// ---- UA-Binary bare-body builders -----------------------------

func fourByteNode(ns byte, id uint16) []byte {
	var u16 [2]byte
	binary.LittleEndian.PutUint16(u16[:], id)
	return []byte{byte(wire.NodeIDFourByte), ns, u16[0], u16[1]}
}

func minimalRequestHeader() []byte {
	b := []byte{byte(wire.NodeIDTwoByte), 0x00}         // AuthenticationToken null
	b = append(b, make([]byte, 8)...)                   // Timestamp
	b = append(b, make([]byte, 4)...)                   // RequestHandle
	b = append(b, make([]byte, 4)...)                   // ReturnDiagnostics
	b = append(b, 0xFF, 0xFF, 0xFF, 0xFF)               // AuditEntryId null
	b = append(b, make([]byte, 4)...)                   // TimeoutHint
	b = append(b, byte(wire.NodeIDTwoByte), 0x00, 0x00) // AdditionalHeader null ExtObj
	return b
}

// bareService builds a minimal bare message with the given TypeId and a
// RequestHeader. Enough for classification; the service-specific tail
// is empty (fine for non-mutating services the gate never deep-parses).
func bareService(typeID uint16) []byte {
	b := fourByteNode(0, typeID)
	return append(b, minimalRequestHeader()...)
}

// bareWrite builds a bare WriteRequest with the given numeric NodeIds.
func bareWrite(nodes []opcua.AllowedNodeID) []byte {
	b := fourByteNode(0, wire.TypeIDWriteRequest)
	b = append(b, minimalRequestHeader()...)
	var u32 [4]byte
	binary.LittleEndian.PutUint32(u32[:], uint32(len(nodes))) // #nosec G115 -- test-bounded
	b = append(b, u32[:]...)
	for _, n := range nodes {
		b = append(b, fourByteNode(byte(n.Namespace), uint16(n.Identifier))...) // #nosec G115 -- test-bounded
		binary.LittleEndian.PutUint32(u32[:], 13)                               // AttributeId
		b = append(b, u32[:]...)
		b = append(b, 0xFF, 0xFF, 0xFF, 0xFF) // IndexRange null
		b = append(b, 0x00)                   // DataValue mask = 0
	}
	return b
}

// bareCall builds a bare CallRequest with the given (object,method)
// numeric NodeId pairs and null InputArguments.
func bareCall(pairs [][2]uint16) []byte {
	b := fourByteNode(0, wire.TypeIDCallRequest)
	b = append(b, minimalRequestHeader()...)
	var u32 [4]byte
	binary.LittleEndian.PutUint32(u32[:], uint32(len(pairs))) // #nosec G115 -- test-bounded
	b = append(b, u32[:]...)
	for _, p := range pairs {
		b = append(b, fourByteNode(0, p[0])...) // ObjectID
		b = append(b, fourByteNode(0, p[1])...) // MethodID
		b = append(b, 0xFF, 0xFF, 0xFF, 0xFF)   // InputArguments: null Variant[]
	}
	return b
}

// postUA renders an HTTP POST carrying a bare UA-Binary body.
func postUA(body []byte) []byte {
	hdr := "POST / HTTP/1.1\r\nHost: plc.test\r\n" +
		"Content-Type: application/octet-stream\r\n" +
		"Content-Length: " + itoa(len(body)) + "\r\n\r\n"
	return append([]byte(hdr), body...)
}

// ---- AllowlistHash / token scoping ----------------------------

func TestTokenScopedToTransport(t *testing.T) {
	// Same allowlist, but an opcua (TCP) token must NOT authorise the
	// opcuahttps gate: the Protocol field differs, so the derived
	// tokens differ.
	target := "plc.test:4843"
	svcs := []opcua.AllowedService{{TypeID: wire.TypeIDWriteRequest}}
	httpsMut := uahttps.SessionMutation(target, svcs, nil, nil, nil, 0)
	tcpMut := opcua.SessionMutation(target, svcs)
	dv := &fakeDeriver{key: []byte(testDeriverKey)}
	httpsTok, err := confirm.ExpectedToken(httpsMut, dv)
	if err != nil {
		t.Fatal(err)
	}
	tcpTok, err := confirm.ExpectedToken(tcpMut, dv)
	if err != nil {
		t.Fatal(err)
	}
	if httpsTok == tcpTok {
		t.Fatal("opcuahttps and opcua tokens must differ for the same allowlist")
	}
}

// ---- Authorise ------------------------------------------------

func TestAuthorise_BadTokenDenied(t *testing.T) {
	target := "plc.test:4843"
	h := &uahttps.WriteGatedHandler{
		Target:  target,
		Deriver: &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor: &fakeAuditor{},
		SessionConfirm: confirm.Confirm{
			AcceptsWrites: true,
			ConfirmTarget: target,
			ConfirmToken:  "wrong",
		},
	}
	if err := h.Authorise(context.Background()); err == nil {
		t.Fatal("expected bad-token error")
	}
}

func TestHandle_UnauthorisedErrors(t *testing.T) {
	h := &uahttps.WriteGatedHandler{
		Target:  "plc.test:4843",
		Deriver: &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor: &fakeAuditor{},
	}
	if err := h.Handle(context.Background(), &ioPair{}, &ioPair{}); err == nil {
		t.Fatal("expected ErrSessionNotAuthorised")
	}
}

type ioPair struct{}

func (*ioPair) Read(_ []byte) (int, error)  { return 0, io.EOF }
func (*ioPair) Write(b []byte) (int, error) { return len(b), nil }

// ---- Routing --------------------------------------------------

func TestGET_Passes(t *testing.T) {
	client, srv := driveSession(t, allowlist{})
	_, _ = client.Write([]byte("GET / HTTP/1.1\r\nHost: plc.test\r\n\r\n"))
	resp := readResponse(t, client)
	if !resp.FromUpstream {
		t.Fatalf("GET should reach upstream; resp=%+v", resp)
	}
	waitSeen(t, srv)
}

func TestReadRequest_Passes(t *testing.T) {
	// ReadRequest (631) is non-mutating: forwarded even with an empty
	// allowlist.
	client, srv := driveSession(t, allowlist{})
	_, _ = client.Write(postUA(bareService(wire.TypeIDReadRequest)))
	resp := readResponse(t, client)
	if !resp.FromUpstream {
		t.Fatalf("ReadRequest should reach upstream; resp=%+v", resp)
	}
	waitSeen(t, srv)
}

func TestWriteRequest_RefusedWhenServiceNotAllowed(t *testing.T) {
	client, srv := driveSession(t, allowlist{}) // no services allowed
	_, _ = client.Write(postUA(bareWrite([]opcua.AllowedNodeID{{Namespace: 2, Identifier: 42}})))
	resp := readResponse(t, client)
	if resp.FromUpstream || resp.GateReason == "" {
		t.Fatalf("WriteRequest must be refused; resp=%+v", resp)
	}
	if id, ok := wire.ServiceTypeIDHTTPS(resp.Body); !ok || id != wire.TypeIDServiceFault {
		t.Fatalf("refusal body must be a ServiceFault (397); got (%d,%t)", id, ok)
	}
	mustNotSee(t, srv)
}

func TestWriteRequest_AllowedServiceLevel(t *testing.T) {
	client, srv := driveSession(t, allowlist{
		services: []opcua.AllowedService{{TypeID: wire.TypeIDWriteRequest}},
	})
	_, _ = client.Write(postUA(bareWrite([]opcua.AllowedNodeID{{Namespace: 2, Identifier: 42}})))
	resp := readResponse(t, client)
	if !resp.FromUpstream {
		t.Fatalf("service-allowed WriteRequest should forward; resp=%+v", resp)
	}
	waitSeen(t, srv)
}

func TestWriteRequest_PerNodeGate(t *testing.T) {
	allow := opcua.AllowedNodeID{Namespace: 2, Identifier: 42}
	a := allowlist{
		services: []opcua.AllowedService{{TypeID: wire.TypeIDWriteRequest}},
		nodeIDs:  []opcua.AllowedNodeID{allow},
	}

	// Allowed node → forwards.
	client, srv := driveSession(t, a)
	_, _ = client.Write(postUA(bareWrite([]opcua.AllowedNodeID{allow})))
	if resp := readResponse(t, client); !resp.FromUpstream {
		t.Fatalf("allowed node should forward; resp=%+v", resp)
	}
	waitSeen(t, srv)

	// Disallowed node → refused.
	client2, srv2 := driveSession(t, a)
	_, _ = client2.Write(postUA(bareWrite([]opcua.AllowedNodeID{{Namespace: 2, Identifier: 99}})))
	if resp := readResponse(t, client2); resp.FromUpstream || resp.GateReason == "" {
		t.Fatalf("disallowed node must be refused; resp=%+v", resp)
	}
	mustNotSee(t, srv2)
}

func TestCallRequest_PerMethodGate(t *testing.T) {
	// Object ns=0;i=85, Method ns=0;i=1234.
	a := allowlist{
		services: []opcua.AllowedService{{TypeID: wire.TypeIDCallRequest}},
		calls:    []opcua.AllowedCallMethod{{ObjectID: "ns=0;i=85", MethodID: "ns=0;i=1234"}},
	}

	client, srv := driveSession(t, a)
	_, _ = client.Write(postUA(bareCall([][2]uint16{{85, 1234}})))
	if resp := readResponse(t, client); !resp.FromUpstream {
		t.Fatalf("allowed method should forward; resp=%+v", resp)
	}
	waitSeen(t, srv)

	client2, srv2 := driveSession(t, a)
	_, _ = client2.Write(postUA(bareCall([][2]uint16{{85, 9999}})))
	if resp := readResponse(t, client2); resp.FromUpstream || resp.GateReason == "" {
		t.Fatalf("disallowed method must be refused; resp=%+v", resp)
	}
	mustNotSee(t, srv2)
}

func TestOversizeBodyRefused(t *testing.T) {
	h := &uahttps.WriteGatedHandler{
		Target:       "plc.test:4843",
		Allowed:      []opcua.AllowedService{{TypeID: wire.TypeIDWriteRequest}},
		MaxBodyBytes: 32,
		Deriver:      &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor:      &fakeAuditor{},
	}
	a := allowlist{services: h.Allowed}
	h.SessionConfirm = confirm.Confirm{
		AcceptsWrites: true,
		ConfirmTarget: "plc.test:4843",
		ConfirmToken:  mintToken(t, "plc.test:4843", a),
	}
	if err := h.Authorise(context.Background()); err != nil {
		t.Fatal(err)
	}
	clientPipe, handlerClientSide := net.Pipe()
	handlerUpstreamSide, originSide := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = clientPipe.Close()
		_ = handlerClientSide.Close()
		_ = handlerUpstreamSide.Close()
		_ = originSide.Close()
	})
	srv := &upstreamServer{}
	go srv.run(originSide)
	go func() { _ = h.Handle(ctx, handlerClientSide, handlerUpstreamSide) }()

	big := make([]byte, 100) // > 32-byte cap
	copy(big, bareWrite([]opcua.AllowedNodeID{{Namespace: 2, Identifier: 42}}))
	_, _ = clientPipe.Write(postUA(big))
	resp := readResponse(t, clientPipe)
	if resp.FromUpstream || resp.GateReason == "" {
		t.Fatalf("oversize body must be refused; resp=%+v", resp)
	}
	mustNotSee(t, srv)
}

func TestCONNECT_Refused(t *testing.T) {
	client, srv := driveSession(t, allowlist{})
	_, _ = client.Write([]byte("CONNECT plc.test:4843 HTTP/1.1\r\nHost: plc.test:4843\r\n\r\n"))
	resp := readResponse(t, client)
	if resp.FromUpstream || resp.GateReason == "" {
		t.Fatalf("CONNECT must be refused; resp=%+v", resp)
	}
	mustNotSee(t, srv)
}

func TestMultipleRequestsInStream(t *testing.T) {
	a := allowlist{services: []opcua.AllowedService{{TypeID: wire.TypeIDWriteRequest}}}
	client, srv := driveSession(t, a)

	// 1) ReadRequest (forward). 2) WriteRequest with 673 NOT... it IS
	// allowed service-wide, so it forwards too. Use a CallRequest that
	// is not allowed to exercise a mid-stream refusal.
	stream := append(postUA(bareService(wire.TypeIDReadRequest)), postUA(bareService(wire.TypeIDCallRequest))...)
	_, _ = client.Write(stream)

	r1 := readResponse(t, client)
	if !r1.FromUpstream {
		t.Fatalf("first (Read) should forward; resp=%+v", r1)
	}
	r2 := readResponse(t, client)
	if r2.FromUpstream || r2.GateReason == "" {
		t.Fatalf("second (Call, not allowed) should be refused; resp=%+v", r2)
	}
	waitSeen(t, srv) // only the Read reached upstream
	if got := len(srv.seen()); got != 1 {
		t.Fatalf("upstream saw %d; want exactly 1 (the Read)", got)
	}
}

// ---- itoa (avoid strconv churn) -------------------------------

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
