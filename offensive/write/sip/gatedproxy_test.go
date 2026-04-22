//go:build offensive

package sip_test

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/textproto"
	"strings"
	"sync"
	"testing"
	"time"

	"local/elsereno/offensive/confirm"
	sipwrite "local/elsereno/offensive/write/sip"
)

// ---- fakes ----------------------------------------------------

type fakeDeriver struct{ key []byte }

func (f *fakeDeriver) Derive(_ string, out []byte) error {
	copy(out, f.key)
	return nil
}

type fakeAuditor struct{ events []confirm.AuditEvent }

func (f *fakeAuditor) Record(_ context.Context, ev confirm.AuditEvent) error {
	f.events = append(f.events, ev)
	return nil
}

const testDeriverKey = "test-key-32-byte-long--------"

// mintToken mints the triple-confirm token so the handler's
// Authorise passes. Same shape as the opcua + modbus test
// helpers.
func mintToken(t *testing.T, target string, allowed []sipwrite.AllowedMethod) string {
	t.Helper()
	mut := sipwrite.SessionMutation(target, allowed)
	tok, err := confirm.ExpectedToken(mut, &fakeDeriver{key: []byte(testDeriverKey)})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// newHandler returns an authorised WriteGatedHandler ready to
// Handle traffic. The fakeAuditor is installed but not exposed —
// the tests here don't assert on audit events (those are covered
// by confirm_test).
func newHandler(t *testing.T, target string, allowed []sipwrite.AllowedMethod) *sipwrite.WriteGatedHandler {
	t.Helper()
	h := &sipwrite.WriteGatedHandler{
		Target:  target,
		Allowed: allowed,
		Deriver: &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor: &fakeAuditor{},
		SessionConfirm: confirm.Confirm{
			AcceptsWrites: true,
			ConfirmTarget: target,
			ConfirmToken:  mintToken(t, target, allowed),
		},
	}
	if err := h.Authorise(context.Background()); err != nil {
		t.Fatal(err)
	}
	return h
}

// driveSession wires net.Pipe pairs between client and upstream,
// starts Handle in a goroutine, and returns (clientConn,
// upstreamSeen). upstreamSeen buffers everything forwarded to the
// upstream so tests can assert on it.
//
// Cleanup is installed via t.Cleanup.
func driveSession(t *testing.T, allowed []sipwrite.AllowedMethod) (net.Conn, *upstreamRecorder) {
	t.Helper()
	target := "sip-server.test:5060"
	h := newHandler(t, target, allowed)

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

	recorder := &upstreamRecorder{done: make(chan struct{})}
	go recorder.run(upstreamReaderSide)
	go func() { _ = h.Handle(ctx, handlerClientSide, upstreamWriterSide) }()

	return clientPipe, recorder
}

// upstreamRecorder captures everything the handler forwards to
// upstream so tests can assert on the forwarded request. All
// access to `data` goes through the mutex so the race detector
// stays quiet when a test asserts while the recorder goroutine
// is still draining.
type upstreamRecorder struct {
	mu   sync.Mutex
	data []byte
	done chan struct{}
}

func (u *upstreamRecorder) run(r io.Reader) {
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			u.mu.Lock()
			u.data = append(u.data, buf[:n]...)
			u.mu.Unlock()
		}
		if err != nil {
			close(u.done)
			return
		}
	}
}

// snapshot returns a copy of the current bytes under the mutex.
func (u *upstreamRecorder) snapshot() []byte {
	u.mu.Lock()
	defer u.mu.Unlock()
	out := make([]byte, len(u.data))
	copy(out, u.data)
	return out
}

// seen waits up to 500 ms for at least minBytes to be observed.
// 500 ms is enough slack for the handler's forward goroutine to
// write a small SIP request on net.Pipe without introducing
// flakiness on a loaded CI runner.
func (u *upstreamRecorder) seen(t *testing.T, minBytes int) string {
	t.Helper()
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		snap := u.snapshot()
		if len(snap) >= minBytes {
			return string(snap)
		}
		time.Sleep(10 * time.Millisecond)
	}
	snap := u.snapshot()
	t.Fatalf("upstream saw %d bytes; wanted ≥ %d", len(snap), minBytes)
	return ""
}

// readSIPResponse reads a SIP status-line + headers from conn
// until the blank-line terminator. Returns the full head.
func readSIPResponse(t *testing.T, conn net.Conn) string {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	br := bufio.NewReader(conn)
	tp := textproto.NewReader(br)
	status, err := tp.ReadLine()
	if err != nil {
		t.Fatalf("read status: %v", err)
	}
	headers, err := tp.ReadMIMEHeader()
	if err != nil {
		t.Fatalf("read headers: %v", err)
	}
	var b strings.Builder
	b.WriteString(status)
	b.WriteString("\r\n")
	for k, vs := range headers {
		for _, v := range vs {
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteString("\r\n")
		}
	}
	return b.String()
}

// ---- AllowlistHash --------------------------------------------

func TestAllowlistHash_OrderInsensitive(t *testing.T) {
	a := []sipwrite.AllowedMethod{{Method: "INVITE"}, {Method: "REGISTER"}}
	b := []sipwrite.AllowedMethod{{Method: "REGISTER"}, {Method: "INVITE"}}
	h1 := sipwrite.AllowlistHash("t", a)
	h2 := sipwrite.AllowlistHash("t", b)
	if h1 != h2 {
		t.Fatalf("hash depends on input order: %x vs %x", h1, h2)
	}
}

func TestAllowlistHash_CaseInsensitive(t *testing.T) {
	a := []sipwrite.AllowedMethod{{Method: "INVITE"}}
	b := []sipwrite.AllowedMethod{{Method: "invite"}}
	h1 := sipwrite.AllowlistHash("t", a)
	h2 := sipwrite.AllowlistHash("t", b)
	if h1 != h2 {
		t.Fatal("hash should fold case: INVITE == invite")
	}
}

func TestAllowlistHash_DifferentTarget(t *testing.T) {
	a := []sipwrite.AllowedMethod{{Method: "INVITE"}}
	h1 := sipwrite.AllowlistHash("host-a:5060", a)
	h2 := sipwrite.AllowlistHash("host-b:5060", a)
	if h1 == h2 {
		t.Fatal("hash should vary with target")
	}
}

// ---- Authorise contract ---------------------------------------

func TestAuthorise_HappyPath(t *testing.T) {
	target := "sip-server.test:5060"
	allowed := []sipwrite.AllowedMethod{{Method: "INVITE"}}
	h := newHandler(t, target, allowed)
	// Second call is a no-op.
	if err := h.Authorise(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestAuthorise_DeniedWithoutToken(t *testing.T) {
	target := "sip-server.test:5060"
	h := &sipwrite.WriteGatedHandler{
		Target:  target,
		Deriver: &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor: &fakeAuditor{},
		SessionConfirm: confirm.Confirm{
			AcceptsWrites: true,
			ConfirmTarget: target,
			ConfirmToken:  "wrong-token",
		},
	}
	if err := h.Authorise(context.Background()); err == nil {
		t.Fatal("expected bad-token error")
	}
}

func TestHandle_UnauthorisedReturnsError(t *testing.T) {
	h := &sipwrite.WriteGatedHandler{
		Target:  "sip-server.test:5060",
		Deriver: &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor: &fakeAuditor{},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err := h.Handle(ctx, &ioPair{}, &ioPair{})
	if err == nil {
		t.Fatal("expected ErrSessionNotAuthorised")
	}
}

// ioPair satisfies io.ReadWriter with empty behaviour for the
// unauthorised-handle test.
type ioPair struct{}

func (*ioPair) Read(_ []byte) (int, error)  { return 0, io.EOF }
func (*ioPair) Write(b []byte) (int, error) { return len(b), nil }

// ---- Routing: always-safe methods -----------------------------

func TestRouting_OPTIONSAlwaysPasses(t *testing.T) {
	client, upstream := driveSession(t, nil) // empty allowlist

	req := "OPTIONS sip:server SIP/2.0\r\n" +
		"Via: SIP/2.0/TCP client.test;branch=z9hG4bK.1\r\n" +
		"From: <sip:caller@client.test>;tag=abc\r\n" +
		"To: <sip:server>\r\n" +
		"Call-ID: c1\r\n" +
		"CSeq: 1 OPTIONS\r\n" +
		"Content-Length: 0\r\n\r\n"
	if _, err := io.WriteString(client, req); err != nil {
		t.Fatalf("write OPTIONS: %v", err)
	}
	// Upstream should receive the OPTIONS.
	seen := upstream.seen(t, 80)
	if !strings.HasPrefix(seen, "OPTIONS sip:server SIP/2.0") {
		t.Fatalf("upstream did not see OPTIONS:\n%s", seen)
	}
}

func TestRouting_BYEAlwaysPasses(t *testing.T) {
	client, upstream := driveSession(t, nil)
	req := "BYE sip:server SIP/2.0\r\n" +
		"Via: SIP/2.0/TCP client.test;branch=z9hG4bK.1\r\n" +
		"From: <sip:a@client.test>;tag=abc\r\n" +
		"To: <sip:server>;tag=xyz\r\n" +
		"Call-ID: c1\r\n" +
		"CSeq: 2 BYE\r\n" +
		"Content-Length: 0\r\n\r\n"
	_, _ = io.WriteString(client, req)
	seen := upstream.seen(t, 60)
	if !strings.HasPrefix(seen, "BYE sip:server SIP/2.0") {
		t.Fatalf("upstream did not see BYE:\n%s", seen)
	}
}

// ---- Routing: gated methods -----------------------------------

func TestRouting_INVITEAllowed(t *testing.T) {
	client, upstream := driveSession(t, []sipwrite.AllowedMethod{{Method: "INVITE"}})
	req := "INVITE sip:dest@server SIP/2.0\r\n" +
		"Via: SIP/2.0/TCP client.test;branch=z9hG4bK.1\r\n" +
		"From: <sip:a@client.test>;tag=abc\r\n" +
		"To: <sip:dest@server>\r\n" +
		"Call-ID: c1\r\n" +
		"CSeq: 1 INVITE\r\n" +
		"Content-Type: application/sdp\r\n" +
		"Content-Length: 23\r\n\r\n" +
		"v=0\r\no=- 0 0 IN IP4 1\r\n\r\n"
	_, _ = io.WriteString(client, req)
	seen := upstream.seen(t, 100)
	if !strings.HasPrefix(seen, "INVITE sip:dest@server SIP/2.0") {
		t.Fatalf("upstream did not see INVITE:\n%s", seen)
	}
	// Body should be forwarded verbatim.
	if !strings.Contains(seen, "v=0") {
		t.Fatalf("body not forwarded:\n%s", seen)
	}
}

func TestRouting_INVITEBlockedReturns405(t *testing.T) {
	// Empty allowlist → INVITE refused.
	client, upstream := driveSession(t, nil)
	req := "INVITE sip:victim@server SIP/2.0\r\n" +
		"Via: SIP/2.0/TCP client.test;branch=z9hG4bK.1\r\n" +
		"From: <sip:a@client.test>;tag=abc\r\n" +
		"To: <sip:victim@server>\r\n" +
		"Call-ID: c1\r\n" +
		"CSeq: 1 INVITE\r\n" +
		"Content-Length: 0\r\n\r\n"
	_, _ = io.WriteString(client, req)
	// Client should get a 405 back.
	resp := readSIPResponse(t, client)
	if !strings.HasPrefix(resp, "SIP/2.0 405 Method Not Allowed") {
		t.Fatalf("client did not see 405:\n%s", resp)
	}
	allow := allowLineFromResponse(t, resp)
	// Allow header should include the always-safe methods but not
	// INVITE.
	for _, m := range []string{"OPTIONS", "ACK", "BYE", "CANCEL", "PRACK"} {
		if !strings.Contains(allow, m) {
			t.Errorf("Allow missing always-safe %s: %q", m, allow)
		}
	}
	if strings.Contains(allow, "INVITE") {
		t.Errorf("Allow should NOT include the refused INVITE: %q", allow)
	}
	// Upstream should NOT have seen anything.
	if snap := upstream.snapshot(); len(snap) != 0 {
		t.Fatalf("upstream saw bytes for a blocked INVITE: %q", string(snap))
	}
}

func TestRouting_REGISTERBlockedReturns405(t *testing.T) {
	client, upstream := driveSession(t, []sipwrite.AllowedMethod{{Method: "INVITE"}}) // INVITE allowed, REGISTER not
	req := "REGISTER sip:server SIP/2.0\r\n" +
		"Via: SIP/2.0/TCP client.test;branch=z9hG4bK.1\r\n" +
		"From: <sip:a@client.test>;tag=abc\r\n" +
		"To: <sip:a@server>\r\n" +
		"Call-ID: c1\r\n" +
		"CSeq: 1 REGISTER\r\n" +
		"Contact: <sip:a@1.2.3.4>\r\n" +
		"Expires: 3600\r\n" +
		"Content-Length: 0\r\n\r\n"
	_, _ = io.WriteString(client, req)
	resp := readSIPResponse(t, client)
	if !strings.HasPrefix(resp, "SIP/2.0 405") {
		t.Fatalf("REGISTER not refused:\n%s", resp)
	}
	allow := allowLineFromResponse(t, resp)
	if !strings.Contains(allow, "INVITE") {
		t.Errorf("Allow should advertise the allowlisted INVITE: %q", allow)
	}
	if snap := upstream.snapshot(); len(snap) != 0 {
		t.Fatalf("upstream saw bytes for a blocked REGISTER: %q", string(snap))
	}
}

func TestRouting_REGISTERAllowed(t *testing.T) {
	client, upstream := driveSession(t, []sipwrite.AllowedMethod{{Method: "REGISTER"}})
	req := "REGISTER sip:server SIP/2.0\r\n" +
		"Via: SIP/2.0/TCP client.test;branch=z9hG4bK.1\r\n" +
		"From: <sip:a@client.test>;tag=abc\r\n" +
		"To: <sip:a@server>\r\n" +
		"Call-ID: c1\r\n" +
		"CSeq: 1 REGISTER\r\n" +
		"Contact: <sip:a@1.2.3.4>\r\n" +
		"Content-Length: 0\r\n\r\n"
	_, _ = io.WriteString(client, req)
	seen := upstream.seen(t, 80)
	if !strings.HasPrefix(seen, "REGISTER sip:server SIP/2.0") {
		t.Fatalf("upstream did not see allowed REGISTER:\n%s", seen)
	}
}

// ---- Routing: robustness / edge cases -------------------------

func TestRouting_MalformedRequestLineFailsFast(t *testing.T) {
	client, _ := driveSession(t, nil)
	// Missing SIP/2.0 terminator → parseMethod returns false.
	req := "INVITE sip:server\r\n\r\n"
	_, _ = io.WriteString(client, req)
	// Give the handler a moment to notice.
	time.Sleep(100 * time.Millisecond)
	// The handler returned an error; the next client read should
	// EOF.
	_ = client.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 1)
	n, _ := client.Read(buf)
	if n != 0 {
		t.Fatalf("expected no reply for malformed request, got %d bytes", n)
	}
}

func TestRouting_LowercaseMethodIsCanonicalised(t *testing.T) {
	// The test sends "Invite" — the allowlist holds "INVITE".
	// allow() must fold case.
	client, upstream := driveSession(t, []sipwrite.AllowedMethod{{Method: "INVITE"}})
	req := "Invite sip:dest@server SIP/2.0\r\n" +
		"Via: SIP/2.0/TCP c.test;branch=z9hG4bK.1\r\n" +
		"From: <sip:a@c.test>;tag=x\r\n" +
		"To: <sip:dest@server>\r\n" +
		"Call-ID: c1\r\n" +
		"CSeq: 1 Invite\r\n" +
		"Content-Length: 0\r\n\r\n"
	_, _ = io.WriteString(client, req)
	seen := upstream.seen(t, 80)
	if !strings.HasPrefix(seen, "Invite sip:dest@server SIP/2.0") {
		t.Fatalf("upstream did not see mixed-case Invite:\n%s", seen)
	}
}

func TestRouting_MultipleRequestsInOneStream(t *testing.T) {
	// Pipeline two requests: OPTIONS (always safe) then INVITE
	// (blocked). Handler must process both, forward the first,
	// refuse the second.
	client, upstream := driveSession(t, nil)
	_, _ = io.WriteString(client,
		"OPTIONS sip:s SIP/2.0\r\n"+
			"Via: SIP/2.0/TCP c;branch=z9hG4bK.1\r\n"+
			"From: <sip:a@c>;tag=x\r\n"+
			"To: <sip:s>\r\n"+
			"Call-ID: c1\r\n"+
			"CSeq: 1 OPTIONS\r\n"+
			"Content-Length: 0\r\n\r\n"+
			"INVITE sip:s SIP/2.0\r\n"+
			"Via: SIP/2.0/TCP c;branch=z9hG4bK.2\r\n"+
			"From: <sip:a@c>;tag=x\r\n"+
			"To: <sip:s>\r\n"+
			"Call-ID: c2\r\n"+
			"CSeq: 1 INVITE\r\n"+
			"Content-Length: 0\r\n\r\n")
	// Upstream should see the OPTIONS only.
	seen := upstream.seen(t, 60)
	if !strings.HasPrefix(seen, "OPTIONS sip:s SIP/2.0") {
		t.Fatalf("upstream expected OPTIONS first:\n%s", seen)
	}
	if strings.Contains(seen, "INVITE") {
		t.Fatalf("upstream should NOT have seen the blocked INVITE:\n%s", seen)
	}
	// Client should see a 405 for the INVITE.
	resp := readSIPResponse(t, client)
	if !strings.HasPrefix(resp, "SIP/2.0 405") {
		t.Fatalf("expected 405 for second (INVITE) request:\n%s", resp)
	}
}

// ---- Allow: header composition --------------------------------

func TestAllowHeader_IncludesAllowlistedMethods(t *testing.T) {
	client, _ := driveSession(t, []sipwrite.AllowedMethod{
		{Method: "INVITE"},
		{Method: "REGISTER"},
	})
	// Send a MESSAGE (not allowlisted, not always-safe) → 405.
	_, _ = io.WriteString(client,
		"MESSAGE sip:s SIP/2.0\r\n"+
			"Via: SIP/2.0/TCP c;branch=z9hG4bK.1\r\n"+
			"From: <sip:a@c>;tag=x\r\n"+
			"To: <sip:s>\r\n"+
			"Call-ID: c1\r\n"+
			"CSeq: 1 MESSAGE\r\n"+
			"Content-Length: 0\r\n\r\n")
	resp := readSIPResponse(t, client)
	// Extract the Allow line specifically — the echoed CSeq and
	// other headers can legitimately contain method names.
	allow := allowLineFromResponse(t, resp)
	// Allow must contain INVITE + REGISTER + always-safe.
	for _, m := range []string{"INVITE", "REGISTER", "OPTIONS", "ACK", "BYE", "CANCEL", "PRACK"} {
		if !strings.Contains(allow, m) {
			t.Errorf("Allow header missing %s: %q", m, allow)
		}
	}
	// Must NOT contain MESSAGE (the refused method).
	if strings.Contains(allow, "MESSAGE") {
		t.Errorf("Allow header should not advertise MESSAGE: %q", allow)
	}
}

// allowLineFromResponse pulls the value of the Allow: header
// (case-insensitive) out of a serialised SIP response head. Fails
// the test if the header is missing.
func allowLineFromResponse(t *testing.T, resp string) string {
	t.Helper()
	for _, ln := range strings.Split(resp, "\r\n") {
		// Canonicalised MIME header names are Title-Case by the
		// http/textproto serializer we're reading with.
		if strings.HasPrefix(strings.ToLower(ln), "allow:") {
			_, v, _ := strings.Cut(ln, ":")
			return strings.TrimSpace(v)
		}
	}
	t.Fatalf("no Allow header in response:\n%s", resp)
	return ""
}
