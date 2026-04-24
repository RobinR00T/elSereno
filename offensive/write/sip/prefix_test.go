//go:build offensive

package sip_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"local/elsereno/offensive/confirm"
	sipwrite "local/elsereno/offensive/write/sip"
)

// ---- AllowlistHashWithPrefixes ------------------------------

func TestAllowlistHashWithPrefixes_EmptyMatchesV14(t *testing.T) {
	methods := []sipwrite.AllowedMethod{{Method: "INVITE"}}
	h14 := sipwrite.AllowlistHash("pbx:5060", methods)
	h19 := sipwrite.AllowlistHashWithPrefixes("pbx:5060", methods, nil)
	if !bytes.Equal(h14[:], h19[:]) {
		t.Fatalf("v1.9 hash with empty prefixes differs from v1.4: %x vs %x", h19, h14)
	}
}

func TestAllowlistHashWithPrefixes_Changes(t *testing.T) {
	methods := []sipwrite.AllowedMethod{{Method: "INVITE"}}
	prefixes := []sipwrite.AllowedToURIPrefix{{Prefix: "+34"}}
	h14 := sipwrite.AllowlistHash("pbx:5060", methods)
	h19 := sipwrite.AllowlistHashWithPrefixes("pbx:5060", methods, prefixes)
	if bytes.Equal(h14[:], h19[:]) {
		t.Fatal("v1.9 hash with prefixes must differ from v1.4")
	}
}

func TestAllowlistHashWithPrefixes_OrderInsensitive(t *testing.T) {
	methods := []sipwrite.AllowedMethod{{Method: "INVITE"}}
	a := []sipwrite.AllowedToURIPrefix{{Prefix: "+34"}, {Prefix: "+44"}}
	b := []sipwrite.AllowedToURIPrefix{{Prefix: "+44"}, {Prefix: "+34"}}
	ha := sipwrite.AllowlistHashWithPrefixes("t", methods, a)
	hb := sipwrite.AllowlistHashWithPrefixes("t", methods, b)
	if !bytes.Equal(ha[:], hb[:]) {
		t.Fatal("hash depends on prefix input order")
	}
}

func TestAllowlistHashWithPrefixes_NormalizesInput(t *testing.T) {
	methods := []sipwrite.AllowedMethod{{Method: "INVITE"}}
	a := []sipwrite.AllowedToURIPrefix{{Prefix: "  SIP:+34  "}}
	b := []sipwrite.AllowedToURIPrefix{{Prefix: "+34"}}
	ha := sipwrite.AllowlistHashWithPrefixes("t", methods, a)
	hb := sipwrite.AllowlistHashWithPrefixes("t", methods, b)
	if !bytes.Equal(ha[:], hb[:]) {
		t.Fatal("canonicalisation not equivalent")
	}
}

// driveSessionWithPrefixes wires a WriteGatedHandler with the
// v1.9 prefix allowlist field onto net.Pipe pairs + returns the
// client-side conn + the upstream recorder.
func driveSessionWithPrefixes(t *testing.T, methods []sipwrite.AllowedMethod, prefixes []sipwrite.AllowedToURIPrefix) (net.Conn, *upstreamRecorder) {
	t.Helper()
	target := "sip-server.test:5060"
	h := &sipwrite.WriteGatedHandler{
		Target:               target,
		Allowed:              methods,
		AllowedToURIPrefixes: prefixes,
		Deriver:              &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor:              &fakeAuditor{},
	}
	mut := sipwrite.SessionMutationWithPrefixes(target, methods, prefixes)
	tok, err := confirm.ExpectedToken(mut, &fakeDeriver{key: []byte(testDeriverKey)})
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
	recorder := &upstreamRecorder{done: make(chan struct{})}
	go recorder.run(upstreamReaderSide)
	go func() { _ = h.Handle(ctx, handlerClientSide, upstreamWriterSide) }()
	return clientPipe, recorder
}

// ---- End-to-end gate with the prefix allowlist active -------

func TestRouting_INVITEAllowedByDestinationPrefix(t *testing.T) {
	client, upstream := driveSessionWithPrefixes(t,
		[]sipwrite.AllowedMethod{{Method: "INVITE"}},
		[]sipwrite.AllowedToURIPrefix{{Prefix: "+34"}, {Prefix: "+44"}},
	)
	req := "INVITE sip:+34600123456@pbx SIP/2.0\r\n" +
		"Via: SIP/2.0/TCP c;branch=z9hG4bK.1\r\n" +
		"From: <sip:a@c>;tag=x\r\n" +
		"To: <sip:+34600123456@pbx>\r\n" +
		"Call-ID: c1\r\n" +
		"CSeq: 1 INVITE\r\n" +
		"Content-Length: 0\r\n\r\n"
	_, _ = io.WriteString(client, req)
	seen := upstream.seen(t, 60)
	if !strings.HasPrefix(seen, "INVITE sip:+34600123456@pbx SIP/2.0") {
		t.Fatalf("upstream did not see allowed INVITE:\n%s", seen)
	}
}

func TestRouting_INVITEBlockedByDestinationPrefix(t *testing.T) {
	client, upstream := driveSessionWithPrefixes(t,
		[]sipwrite.AllowedMethod{{Method: "INVITE"}},
		[]sipwrite.AllowedToURIPrefix{{Prefix: "+34"}},
	)
	// +900 = premium-rate → should be refused even though
	// INVITE is in the method allowlist.
	req := "INVITE sip:+900555@pbx SIP/2.0\r\n" +
		"Via: SIP/2.0/TCP c;branch=z9hG4bK.1\r\n" +
		"From: <sip:a@c>;tag=x\r\n" +
		"To: <sip:+900555@pbx>\r\n" +
		"Call-ID: c1\r\n" +
		"CSeq: 1 INVITE\r\n" +
		"Content-Length: 0\r\n\r\n"
	_, _ = io.WriteString(client, req)
	resp := readSIPResponse(t, client)
	if !strings.HasPrefix(resp, "SIP/2.0 403 Forbidden") { //nolint:misspell // RFC 3261 §21.4 canonical spelling
		t.Fatalf("expected 403, got:\n%s", resp)
	}
	if !strings.Contains(resp, "X-Elsereno-Gate-Reason:") {
		t.Errorf("refusal should include X-Elsereno-Gate-Reason: %s", resp)
	}
	time.Sleep(50 * time.Millisecond)
	if snap := upstream.snapshot(); len(snap) != 0 {
		t.Fatalf("upstream saw bytes for a blocked INVITE destination: %q", snap)
	}
}

func TestRouting_EmptyPrefixListFallsBackToV14(t *testing.T) {
	// Empty prefix list → v1.4 behaviour: INVITE passes as long
	// as INVITE is in the method allowlist.
	client, upstream := driveSessionWithPrefixes(t,
		[]sipwrite.AllowedMethod{{Method: "INVITE"}},
		nil, // no prefix gating
	)
	req := "INVITE sip:+900anywhere@pbx SIP/2.0\r\n" +
		"Via: SIP/2.0/TCP c;branch=z9hG4bK.1\r\n" +
		"From: <sip:a@c>;tag=x\r\n" +
		"To: <sip:+900anywhere@pbx>\r\n" +
		"Call-ID: c1\r\n" +
		"CSeq: 1 INVITE\r\n" +
		"Content-Length: 0\r\n\r\n"
	_, _ = io.WriteString(client, req)
	seen := upstream.seen(t, 60)
	if !strings.HasPrefix(seen, "INVITE sip:+900anywhere@pbx SIP/2.0") {
		t.Fatalf("v1.4 fallback: upstream should have seen the INVITE:\n%s", seen)
	}
}

// Other gated methods (REGISTER, MESSAGE, …) are NOT affected
// by the prefix allowlist — only INVITE is gated on
// destination.
func TestRouting_RegisterNotAffectedByPrefixAllowlist(t *testing.T) {
	client, upstream := driveSessionWithPrefixes(t,
		[]sipwrite.AllowedMethod{{Method: "REGISTER"}},
		[]sipwrite.AllowedToURIPrefix{{Prefix: "+34"}},
	)
	// REGISTER to a non-+34 destination — should STILL pass
	// because prefix list gates INVITE only.
	req := "REGISTER sip:server SIP/2.0\r\n" +
		"Via: SIP/2.0/TCP c;branch=z9hG4bK.1\r\n" +
		"From: <sip:a@server>;tag=x\r\n" +
		"To: <sip:a@server>\r\n" +
		"Call-ID: c1\r\n" +
		"CSeq: 1 REGISTER\r\n" +
		"Content-Length: 0\r\n\r\n"
	_, _ = io.WriteString(client, req)
	seen := upstream.seen(t, 60)
	if !strings.HasPrefix(seen, "REGISTER sip:server SIP/2.0") {
		t.Fatalf("REGISTER should have passed (prefix list only gates INVITE):\n%s", seen)
	}
}
