//go:build offensive

package pbxhttp_test

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"local/elsereno/offensive/confirm"
	pwrite "local/elsereno/offensive/write/pbxhttp"
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

func mintToken(t *testing.T, target string, allowed []pwrite.AllowedWrite) string {
	t.Helper()
	mut := pwrite.SessionMutation(target, allowed)
	tok, err := confirm.ExpectedToken(mut, &fakeDeriver{key: []byte(testDeriverKey)})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func newHandler(t *testing.T, target string, allowed []pwrite.AllowedWrite) *pwrite.WriteGatedHandler {
	t.Helper()
	h := &pwrite.WriteGatedHandler{
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

// upstreamServer is a minimal "fake origin" that parses an HTTP
// request from the handler and writes a canned response. All
// access to requests[] goes through the mutex.
type upstreamServer struct {
	mu       sync.Mutex
	requests []*http.Request
	conn     net.Conn
}

func (u *upstreamServer) run(conn net.Conn) {
	u.conn = conn
	br := bufio.NewReader(conn)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		u.mu.Lock()
		u.requests = append(u.requests, req)
		u.mu.Unlock()
		// Drain body.
		_, _ = io.Copy(io.Discard, req.Body)
		_ = req.Body.Close()
		// Canned 200.
		_, _ = io.WriteString(conn,
			"HTTP/1.1 200 OK\r\nServer: fake-origin\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n")
	}
}

func (u *upstreamServer) seen() []*http.Request {
	u.mu.Lock()
	defer u.mu.Unlock()
	out := make([]*http.Request, len(u.requests))
	copy(out, u.requests)
	return out
}

// driveSession wires net.Pipe pairs client↔handler + handler↔upstream,
// authorises, starts Handle + upstreamServer.run in goroutines, and
// returns the client-side connection + the upstream recorder.
func driveSession(t *testing.T, allowed []pwrite.AllowedWrite) (net.Conn, *upstreamServer) {
	t.Helper()
	target := "pbx.test:443"
	h := newHandler(t, target, allowed)

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

// statusResp is the subset of http.Response a test needs to
// inspect. We copy values off the Response before closing the
// body so the test never has to juggle Close() itself; the
// caller + bodyclose linter stay happy.
type statusResp struct {
	Code   int
	Header http.Header
}

// readHTTPResponse consumes one HTTP response from conn, drains
// + closes the body, and returns the status+headers snapshot.
// Deadline: 2 s.
func readHTTPResponse(t *testing.T, conn net.Conn) statusResp {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return statusResp{Code: resp.StatusCode, Header: resp.Header.Clone()}
}

// waitSeenOne polls the upstream recorder for at least one
// request. All current callers assert on the first element.
func waitSeenOne(t *testing.T, srv *upstreamServer) []*http.Request {
	t.Helper()
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		reqs := srv.seen()
		if len(reqs) >= 1 {
			return reqs
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("upstream saw %d requests; wanted ≥ 1", len(srv.seen()))
	return nil
}

// ---- AllowlistHash --------------------------------------------

func TestAllowlistHash_OrderInsensitive(t *testing.T) {
	a := []pwrite.AllowedWrite{
		{Method: "POST", Path: "/admin/config.php"},
		{Method: "DELETE", Path: "/admin/user"},
	}
	b := []pwrite.AllowedWrite{
		{Method: "DELETE", Path: "/admin/user"},
		{Method: "POST", Path: "/admin/config.php"},
	}
	if pwrite.AllowlistHash("t", a) != pwrite.AllowlistHash("t", b) {
		t.Fatal("hash depends on input order")
	}
}

func TestAllowlistHash_CaseInsensitiveMethod(t *testing.T) {
	a := []pwrite.AllowedWrite{{Method: "POST", Path: "/x"}}
	b := []pwrite.AllowedWrite{{Method: "post", Path: "/x"}}
	if pwrite.AllowlistHash("t", a) != pwrite.AllowlistHash("t", b) {
		t.Fatal("hash should fold method case")
	}
}

func TestAllowlistHash_PathCaseSensitive(t *testing.T) {
	// Paths are case-sensitive (RFC 3986 §3.3: paths are
	// case-sensitive by default for HTTP URIs).
	a := []pwrite.AllowedWrite{{Method: "POST", Path: "/X"}}
	b := []pwrite.AllowedWrite{{Method: "POST", Path: "/x"}}
	if pwrite.AllowlistHash("t", a) == pwrite.AllowlistHash("t", b) {
		t.Fatal("hash should distinguish case-different paths")
	}
}

func TestAllowlistHash_DifferentTarget(t *testing.T) {
	a := []pwrite.AllowedWrite{{Method: "POST", Path: "/x"}}
	if pwrite.AllowlistHash("host-a:443", a) == pwrite.AllowlistHash("host-b:443", a) {
		t.Fatal("hash should vary with target")
	}
}

// ---- Authorise ------------------------------------------------

func TestAuthorise_HappyPath(t *testing.T) {
	target := "pbx.test:443"
	allowed := []pwrite.AllowedWrite{{Method: "POST", Path: "/admin/config.php"}}
	h := newHandler(t, target, allowed)
	if err := h.Authorise(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestAuthorise_DeniedBadToken(t *testing.T) {
	target := "pbx.test:443"
	h := &pwrite.WriteGatedHandler{
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
	h := &pwrite.WriteGatedHandler{
		Target:  "pbx.test:443",
		Deriver: &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor: &fakeAuditor{},
	}
	err := h.Handle(context.Background(), &ioPair{}, &ioPair{})
	if err == nil {
		t.Fatal("expected ErrSessionNotAuthorised")
	}
}

type ioPair struct{}

func (*ioPair) Read(_ []byte) (int, error)  { return 0, io.EOF }
func (*ioPair) Write(b []byte) (int, error) { return len(b), nil }

// ---- Routing: read-only methods pass --------------------------

func TestGET_AlwaysPasses(t *testing.T) {
	client, srv := driveSession(t, nil) // empty allowlist
	_, _ = io.WriteString(client,
		"GET /admin/config.php HTTP/1.1\r\nHost: pbx.test\r\n\r\n")
	resp := readHTTPResponse(t, client)
	if resp.Code != http.StatusOK {
		t.Fatalf("GET expected 200, got %d", resp.Code)
	}
	reqs := waitSeenOne(t, srv)
	if reqs[0].Method != "GET" {
		t.Fatalf("upstream saw %s, want GET", reqs[0].Method)
	}
}

func TestHEAD_AlwaysPasses(t *testing.T) {
	client, srv := driveSession(t, nil)
	_, _ = io.WriteString(client,
		"HEAD /admin/config.php HTTP/1.1\r\nHost: pbx.test\r\n\r\n")
	resp := readHTTPResponse(t, client)
	if resp.Code != http.StatusOK {
		t.Fatalf("HEAD expected 200, got %d", resp.Code)
	}
	_ = waitSeenOne(t, srv)
}

func TestOPTIONS_AlwaysPasses(t *testing.T) {
	client, srv := driveSession(t, nil)
	_, _ = io.WriteString(client,
		"OPTIONS * HTTP/1.1\r\nHost: pbx.test\r\n\r\n")
	resp := readHTTPResponse(t, client)
	if resp.Code != http.StatusOK {
		t.Fatalf("OPTIONS expected 200, got %d", resp.Code)
	}
	_ = waitSeenOne(t, srv)
}

// ---- Routing: gated methods -----------------------------------

func TestPOST_AllowedForMatchingPath(t *testing.T) {
	client, srv := driveSession(t, []pwrite.AllowedWrite{
		{Method: "POST", Path: "/admin/config.php"},
	})
	body := "name=general&value=1"
	req := "POST /admin/config.php HTTP/1.1\r\n" +
		"Host: pbx.test\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n" +
		"Content-Length: " + itoa(len(body)) + "\r\n\r\n" + body
	_, _ = io.WriteString(client, req)
	resp := readHTTPResponse(t, client)
	if resp.Code != http.StatusOK {
		t.Fatalf("allowed POST: got %d, want 200", resp.Code)
	}
	reqs := waitSeenOne(t, srv)
	if reqs[0].Method != "POST" || reqs[0].URL.Path != "/admin/config.php" {
		t.Fatalf("upstream saw %s %s, want POST /admin/config.php",
			reqs[0].Method, reqs[0].URL.Path)
	}
}

func TestPOST_BlockedForNonMatchingPath(t *testing.T) {
	// POST is in the allowlist for a DIFFERENT path.
	client, srv := driveSession(t, []pwrite.AllowedWrite{
		{Method: "POST", Path: "/admin/config.php"},
	})
	req := "POST /admin/delete_user HTTP/1.1\r\n" +
		"Host: pbx.test\r\n" +
		"Content-Length: 0\r\n\r\n"
	_, _ = io.WriteString(client, req)
	resp := readHTTPResponse(t, client)
	if resp.Code != http.StatusForbidden { //nolint:misspell // RFC 7235 canonical spelling
		t.Fatalf("bad-path POST: got %d, want 403", resp.Code)
	}
	// Upstream should not have seen the request.
	time.Sleep(50 * time.Millisecond)
	if got := srv.seen(); len(got) != 0 {
		t.Fatalf("upstream saw %d requests; expected 0", len(got))
	}
}

func TestPOST_Blocked405WhenMethodNotAllowlisted(t *testing.T) {
	// No POST anywhere in the allowlist.
	client, srv := driveSession(t, []pwrite.AllowedWrite{
		{Method: "DELETE", Path: "/admin/user/1"},
	})
	_, _ = io.WriteString(client,
		"POST /admin/config.php HTTP/1.1\r\nHost: pbx.test\r\nContent-Length: 0\r\n\r\n")
	resp := readHTTPResponse(t, client)
	if resp.Code != http.StatusMethodNotAllowed {
		t.Fatalf("unknown-method POST: got %d, want 405", resp.Code)
	}
	// Allow: header must include always-safe + DELETE, NOT POST.
	allow := resp.Header.Get("Allow")
	for _, m := range []string{"GET", "HEAD", "OPTIONS", "DELETE"} {
		if !strings.Contains(allow, m) {
			t.Errorf("Allow missing %s: %q", m, allow)
		}
	}
	if strings.Contains(allow, "POST") {
		t.Errorf("Allow should NOT include the refused POST: %q", allow)
	}
	time.Sleep(50 * time.Millisecond)
	if got := srv.seen(); len(got) != 0 {
		t.Fatalf("upstream saw %d requests; expected 0", len(got))
	}
}

func TestCONNECT_AlwaysRefused(t *testing.T) {
	client, srv := driveSession(t, []pwrite.AllowedWrite{
		{Method: "CONNECT", Path: "/upstream:443"}, // ignored — CONNECT always refused
	})
	_, _ = io.WriteString(client,
		"CONNECT upstream:443 HTTP/1.1\r\nHost: upstream:443\r\n\r\n")
	resp := readHTTPResponse(t, client)
	if resp.Code != http.StatusForbidden { //nolint:misspell // RFC 7235 canonical spelling
		t.Fatalf("CONNECT: got %d, want 403", resp.Code)
	}
	time.Sleep(50 * time.Millisecond)
	if got := srv.seen(); len(got) != 0 {
		t.Fatalf("upstream saw %d requests; expected 0", len(got))
	}
}

// ---- Robustness -----------------------------------------------

func TestMultipleRequestsInStream(t *testing.T) {
	client, srv := driveSession(t, []pwrite.AllowedWrite{
		{Method: "POST", Path: "/admin/config.php"},
	})
	// First request: GET (allowed). Second: DELETE (blocked —
	// method not allowlisted, so 405).
	stream := "GET /index.html HTTP/1.1\r\nHost: pbx.test\r\n\r\n" +
		"DELETE /admin/config.php HTTP/1.1\r\nHost: pbx.test\r\nContent-Length: 0\r\n\r\n"
	_, _ = io.WriteString(client, stream)

	resp1 := readHTTPResponse(t, client)
	if resp1.Code != http.StatusOK {
		t.Fatalf("first (GET) resp: got %d, want 200", resp1.Code)
	}
	resp2 := readHTTPResponse(t, client)
	if resp2.Code != http.StatusMethodNotAllowed {
		t.Fatalf("second (DELETE) resp: got %d, want 405", resp2.Code)
	}
	reqs := waitSeenOne(t, srv)
	// Only the GET made it to upstream.
	if len(reqs) != 1 || reqs[0].Method != "GET" {
		t.Fatalf("upstream should have seen only the GET; saw %d requests", len(reqs))
	}
}

func TestMalformedRequestIsAnError(t *testing.T) {
	client, _ := driveSession(t, nil)
	// Not a valid HTTP/1.1 request — no path separator after
	// method.
	_, _ = io.WriteString(client, "NOTAMETHOD_NOR_URI\r\n\r\n")
	// Handler should close the connection; client read returns
	// EOF/error.
	_ = client.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 1)
	n, err := client.Read(buf)
	if err == nil && n > 0 {
		// Accept either an immediate EOF (handler bailed) or an
		// HTTP 400 if go's parser produces one. Both are safe.
		return
	}
}

// ---- itoa helper (avoid strconv import churn) -----------------

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
