//go:build offensive

package main

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

	"local/elsereno/internal/proxy"
	"local/elsereno/offensive/confirm"
	bacwrite "local/elsereno/offensive/write/bacnet"
	iaxwrite "local/elsereno/offensive/write/iax2"
	modwrite "local/elsereno/offensive/write/modbus"
	opwrite "local/elsereno/offensive/write/opcua"
	pbxwrite "local/elsereno/offensive/write/pbxhttp"
	sipwrite "local/elsereno/offensive/write/sip"
)

// ---- buildGatedHandler plugin dispatch ------------------------

func TestBuildGatedHandler_SIP(t *testing.T) {
	// runtime nil is fine — buildGatedHandler only reads
	// rt.Vault + rt.Auditor when the handler is actually
	// invoked.
	opts := proxyListenOpts{
		plugin:  "sip",
		target:  "pbx.test:5060",
		methods: []string{"INVITE", "REGISTER"},
	}
	rt := &offensiveRuntime{}
	h, err := buildGatedHandler(opts, rt, confirm.Confirm{})
	if err != nil {
		t.Fatalf("buildGatedHandler: %v", err)
	}
	concrete, ok := h.(*sipwrite.WriteGatedHandler)
	if !ok {
		t.Fatalf("expected *sipwrite.WriteGatedHandler, got %T", h)
	}
	if concrete.Target != "pbx.test:5060" {
		t.Errorf("Target = %q, want pbx.test:5060", concrete.Target)
	}
	if len(concrete.Allowed) != 2 {
		t.Errorf("Allowed len = %d, want 2", len(concrete.Allowed))
	}
}

func TestBuildGatedHandler_IAX2(t *testing.T) {
	opts := proxyListenOpts{
		plugin:     "iax2",
		target:     "pbx.test:4569",
		subclasses: []string{"NEW", "REGREQ"},
	}
	rt := &offensiveRuntime{}
	h, err := buildGatedHandler(opts, rt, confirm.Confirm{})
	if err != nil {
		t.Fatalf("buildGatedHandler: %v", err)
	}
	concrete, ok := h.(*iaxwrite.WriteGatedHandler)
	if !ok {
		t.Fatalf("expected *iaxwrite.WriteGatedHandler, got %T", h)
	}
	if len(concrete.Allowed) != 2 {
		t.Errorf("Allowed len = %d, want 2", len(concrete.Allowed))
	}
}

func TestBuildGatedHandler_IAX2UnknownSubclass(t *testing.T) {
	// Unknown subclass should bubble up an error — better UX than
	// silently accepting an always-safe subclass as "authorised".
	opts := proxyListenOpts{
		plugin:     "iax2",
		target:     "pbx.test:4569",
		subclasses: []string{"HANGUP"}, // always-safe, not valid as an allowlist entry
	}
	rt := &offensiveRuntime{}
	if _, err := buildGatedHandler(opts, rt, confirm.Confirm{}); err == nil {
		t.Fatal("expected error for invalid subclass")
	}
}

func TestBuildGatedHandler_PBXHTTP(t *testing.T) {
	opts := proxyListenOpts{
		plugin:       "pbxhttp",
		target:       "pbx.test:443",
		allowEntries: []string{"POST:/admin/config.php", "DELETE:/admin/user/42"},
	}
	rt := &offensiveRuntime{}
	h, err := buildGatedHandler(opts, rt, confirm.Confirm{})
	if err != nil {
		t.Fatalf("buildGatedHandler: %v", err)
	}
	concrete, ok := h.(*pbxwrite.WriteGatedHandler)
	if !ok {
		t.Fatalf("expected *pbxwrite.WriteGatedHandler, got %T", h)
	}
	if len(concrete.Allowed) != 2 {
		t.Errorf("Allowed len = %d, want 2", len(concrete.Allowed))
	}
}

func TestBuildGatedHandler_PBXHTTPMalformedAllow(t *testing.T) {
	opts := proxyListenOpts{
		plugin:       "pbxhttp",
		target:       "pbx.test:443",
		allowEntries: []string{"POST"},
	}
	rt := &offensiveRuntime{}
	if _, err := buildGatedHandler(opts, rt, confirm.Confirm{}); err == nil {
		t.Fatal("expected error for malformed --allow entry")
	}
}

func TestBuildGatedHandler_UnknownPlugin(t *testing.T) {
	// As of v1.5 chunk 2 the supported set is sip / iax2 /
	// pbxhttp / modbus / opcua / bacnet.
	for _, plugin := range []string{"", "SIP2", "http", "snmp", "unknown"} {
		opts := proxyListenOpts{plugin: plugin, target: "host:1"}
		rt := &offensiveRuntime{}
		if _, err := buildGatedHandler(opts, rt, confirm.Confirm{}); err == nil {
			t.Errorf("--plugin %q: expected error, got none", plugin)
		}
	}
}

func TestBuildGatedHandler_CaseInsensitivePlugin(t *testing.T) {
	// The plugin switch lowercases its key.
	opts := proxyListenOpts{plugin: "SIP", target: "h:1", methods: []string{"OPTIONS"}}
	rt := &offensiveRuntime{}
	if _, err := buildGatedHandler(opts, rt, confirm.Confirm{}); err != nil {
		t.Fatalf("upper-case --plugin SIP should work: %v", err)
	}
}

func TestBuildGatedHandler_Modbus(t *testing.T) {
	opts := proxyListenOpts{
		plugin:    "modbus",
		target:    "plc.test:502",
		functions: []uint{6, 16},
	}
	rt := &offensiveRuntime{}
	h, err := buildGatedHandler(opts, rt, confirm.Confirm{})
	if err != nil {
		t.Fatalf("buildGatedHandler: %v", err)
	}
	concrete, ok := h.(*modwrite.WriteGatedHandler)
	if !ok {
		t.Fatalf("expected *modwrite.WriteGatedHandler, got %T", h)
	}
	if len(concrete.Allowed) != 2 {
		t.Errorf("Allowed len = %d, want 2", len(concrete.Allowed))
	}
}

func TestBuildGatedHandler_ModbusFunctionOutOfRange(t *testing.T) {
	opts := proxyListenOpts{
		plugin:    "modbus",
		target:    "plc.test:502",
		functions: []uint{256}, // > uint8
	}
	rt := &offensiveRuntime{}
	if _, err := buildGatedHandler(opts, rt, confirm.Confirm{}); err == nil {
		t.Fatal("expected out-of-range error")
	}
}

func TestBuildGatedHandler_OPCUA(t *testing.T) {
	opts := proxyListenOpts{
		plugin:   "opcua",
		target:   "plc.test:4840",
		services: []uint{673, 704}, // WriteRequest + CallRequest
	}
	rt := &offensiveRuntime{}
	h, err := buildGatedHandler(opts, rt, confirm.Confirm{})
	if err != nil {
		t.Fatalf("buildGatedHandler: %v", err)
	}
	concrete, ok := h.(*opwrite.WriteGatedHandler)
	if !ok {
		t.Fatalf("expected *opwrite.WriteGatedHandler, got %T", h)
	}
	if len(concrete.Allowed) != 2 {
		t.Errorf("Allowed len = %d, want 2", len(concrete.Allowed))
	}
}

func TestBuildGatedHandler_OPCUAServiceOutOfRange(t *testing.T) {
	opts := proxyListenOpts{
		plugin:   "opcua",
		target:   "plc.test:4840",
		services: []uint{70000}, // > uint16
	}
	rt := &offensiveRuntime{}
	if _, err := buildGatedHandler(opts, rt, confirm.Confirm{}); err == nil {
		t.Fatal("expected out-of-range error")
	}
}

func TestBuildGatedHandler_BACnet(t *testing.T) {
	opts := proxyListenOpts{
		plugin:         "bacnet",
		target:         "bms.test:47808",
		serviceChoices: []uint{15, 20}, // WriteProperty + ReinitializeDevice
	}
	rt := &offensiveRuntime{}
	h, err := buildGatedHandler(opts, rt, confirm.Confirm{})
	if err != nil {
		t.Fatalf("buildGatedHandler: %v", err)
	}
	concrete, ok := h.(*bacwrite.WriteGatedHandler)
	if !ok {
		t.Fatalf("expected *bacwrite.WriteGatedHandler, got %T", h)
	}
	if len(concrete.Allowed) != 2 {
		t.Errorf("Allowed len = %d, want 2", len(concrete.Allowed))
	}
}

// ---- End-to-end: real net.Listener + proxy.Server + SIP gate ----

// TestProxyListen_E2E_SIP spins up a fake SIP origin, then runs
// proxy.Server with the SIP gated handler in front of it. A SIP
// client connects to the proxy, sends an OPTIONS (always-safe)
// followed by an INVITE (not in the allowlist → should get a 405
// back without upstream seeing it). Asserts the allowed traffic
// reached the origin and the refused traffic did not.
func TestProxyListen_E2E_SIP(t *testing.T) {
	// Fake SIP origin: replies 200 OK to anything it reads.
	lc := &net.ListenConfig{}
	originLn, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("origin listen: %v", err)
	}
	defer func() { _ = originLn.Close() }()

	var mu sync.Mutex
	var originSawMethods []string
	go func() {
		conn, aerr := originLn.Accept()
		if aerr != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		br := bufio.NewReader(conn)
		tp := textproto.NewReader(br)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			line, lerr := tp.ReadLine()
			if lerr != nil {
				return
			}
			if method, ok := parseMethodFromLine(line); ok {
				mu.Lock()
				originSawMethods = append(originSawMethods, method)
				mu.Unlock()
			}
			headers, herr := tp.ReadMIMEHeader()
			if herr != nil {
				return
			}
			// Read body if any.
			bodyLen := 0
			if v := headers.Get("Content-Length"); v != "" {
				for _, c := range v {
					if c >= '0' && c <= '9' {
						bodyLen = bodyLen*10 + int(c-'0')
					}
				}
			}
			if bodyLen > 0 {
				_, _ = io.CopyN(io.Discard, br, int64(bodyLen))
			}
			// Reply 200 OK.
			_, _ = io.WriteString(conn,
				"SIP/2.0 200 OK\r\n"+
					"Via: "+headers.Get("Via")+"\r\n"+
					"From: "+headers.Get("From")+"\r\n"+
					"To: "+headers.Get("To")+"\r\n"+
					"Call-ID: "+headers.Get("Call-ID")+"\r\n"+
					"CSeq: "+headers.Get("CSeq")+"\r\n"+
					"Content-Length: 0\r\n\r\n")
		}
	}()

	// Gated handler: allow OPTIONS only (OPTIONS is always-safe
	// so even an empty allowlist would let it through — the
	// real test is the INVITE refusal).
	h := &sipwrite.WriteGatedHandler{
		Target:  originLn.Addr().String(),
		Allowed: nil,
		Deriver: &fakeTokenDeriver{key: []byte("test-key-32-byte-long--------")},
		Auditor: &fakeTokenAuditor{},
		SessionConfirm: confirm.Confirm{
			AcceptsWrites: true,
			ConfirmTarget: originLn.Addr().String(),
			ConfirmToken:  mintTokenForSIPTest(t, originLn.Addr().String(), nil),
		},
	}
	if aerr := h.Authorise(context.Background()); aerr != nil {
		t.Fatalf("Authorise: %v", aerr)
	}

	// Proxy server.
	srv, err := proxy.New(proxy.Options{
		Listen:      "127.0.0.1:0",
		Upstream:    originLn.Addr().String(),
		Handler:     h,
		DialTimeout: 2 * time.Second,
		IdleTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srvErr := make(chan error, 1)
	go func() { srvErr <- srv.Run(ctx) }()

	// Wait for listener to bind.
	deadline := time.Now().Add(2 * time.Second)
	for srv.Addr() == nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if srv.Addr() == nil {
		t.Fatal("proxy listener never bound")
	}

	// Client — connect to the proxy, send OPTIONS then INVITE.
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	client, err := dialer.DialContext(ctx, "tcp", srv.Addr().String())
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	defer func() { _ = client.Close() }()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))

	// OPTIONS should make it upstream.
	_, _ = io.WriteString(client,
		"OPTIONS sip:server SIP/2.0\r\n"+
			"Via: SIP/2.0/TCP c;branch=z9hG4bK.1\r\n"+
			"From: <sip:a@c>;tag=x\r\n"+
			"To: <sip:server>\r\n"+
			"Call-ID: c1\r\n"+
			"CSeq: 1 OPTIONS\r\n"+
			"Content-Length: 0\r\n\r\n")
	// Read the 200 OK.
	br := bufio.NewReader(client)
	tp := textproto.NewReader(br)
	status, err := tp.ReadLine()
	if err != nil {
		t.Fatalf("read OPTIONS response: %v", err)
	}
	if !strings.HasPrefix(status, "SIP/2.0 200") {
		t.Fatalf("OPTIONS response: %q, want 200", status)
	}
	_, _ = tp.ReadMIMEHeader()

	// INVITE should be refused with 405 BEFORE upstream sees it.
	_, _ = io.WriteString(client,
		"INVITE sip:dest SIP/2.0\r\n"+
			"Via: SIP/2.0/TCP c;branch=z9hG4bK.2\r\n"+
			"From: <sip:a@c>;tag=x\r\n"+
			"To: <sip:dest>\r\n"+
			"Call-ID: c2\r\n"+
			"CSeq: 1 INVITE\r\n"+
			"Content-Length: 0\r\n\r\n")
	status, err = tp.ReadLine()
	if err != nil {
		t.Fatalf("read INVITE response: %v", err)
	}
	if !strings.HasPrefix(status, "SIP/2.0 405") {
		t.Fatalf("INVITE response: %q, want 405", status)
	}

	// Give the goroutines a moment to settle, then assert origin
	// only saw OPTIONS.
	time.Sleep(100 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if len(originSawMethods) != 1 || originSawMethods[0] != "OPTIONS" {
		t.Fatalf("origin saw %v; want [OPTIONS] only", originSawMethods)
	}
}

// parseMethodFromLine extracts the first SP-delimited token of a
// SIP request-line for the test origin.
func parseMethodFromLine(line string) (string, bool) {
	if !strings.HasSuffix(line, " SIP/2.0") {
		return "", false
	}
	idx := strings.IndexByte(line, ' ')
	if idx <= 0 {
		return "", false
	}
	return line[:idx], true
}

// fakeTokenDeriver / fakeTokenAuditor are local minimal
// implementations so the E2E test doesn't reach into the per-
// gate _test.go files. (The gate test files define their own
// fakes that aren't exported.)
type fakeTokenDeriver struct{ key []byte }

func (f *fakeTokenDeriver) Derive(_ string, out []byte) error {
	copy(out, f.key)
	return nil
}

type fakeTokenAuditor struct{}

func (*fakeTokenAuditor) Record(_ context.Context, _ confirm.AuditEvent) error { return nil }

func mintTokenForSIPTest(t *testing.T, target string, allowed []sipwrite.AllowedMethod) string {
	t.Helper()
	mut := sipwrite.SessionMutation(target, allowed)
	tok, err := confirm.ExpectedToken(mut, &fakeTokenDeriver{key: []byte("test-key-32-byte-long--------")})
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// Silence "imported but not used" warnings when the iax2 fake
// helpers aren't exercised directly in this file. (iaxwrite is
// used in TestBuildGatedHandler_IAX2 above.)
var _ = iaxwrite.AllowedSubclass{}
var _ = pbxwrite.AllowedWrite{}
