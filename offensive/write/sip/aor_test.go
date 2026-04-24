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

// ---- AllowlistHashWithAORs ----------------------------------

// TestAllowlistHashWithAORs_EmptyMatchesV19 — backwards compat:
// when aors is nil/empty the v1.10 hash MUST equal the v1.9
// hash. Operators who never opt into AOR gating don't need to
// re-mint anything.
func TestAllowlistHashWithAORs_EmptyMatchesV19(t *testing.T) {
	methods := []sipwrite.AllowedMethod{{Method: "REGISTER"}}
	prefixes := []sipwrite.AllowedToURIPrefix{{Prefix: "+34"}}
	h19 := sipwrite.AllowlistHashWithPrefixes("pbx:5060", methods, prefixes)
	h110 := sipwrite.AllowlistHashWithAORs("pbx:5060", methods, prefixes, nil)
	if !bytes.Equal(h19[:], h110[:]) {
		t.Fatalf("v1.10 hash with empty aors differs from v1.9: %x vs %x", h110, h19)
	}
}

// TestAllowlistHashWithAORs_EmptyAndNoPrefixMatchesV14 — double
// backwards compat: empty aors AND empty prefixes → v1.4 hash.
func TestAllowlistHashWithAORs_EmptyAndNoPrefixMatchesV14(t *testing.T) {
	methods := []sipwrite.AllowedMethod{{Method: "REGISTER"}}
	h14 := sipwrite.AllowlistHash("pbx:5060", methods)
	h110 := sipwrite.AllowlistHashWithAORs("pbx:5060", methods, nil, nil)
	if !bytes.Equal(h14[:], h110[:]) {
		t.Fatalf("v1.10 hash with empty aors+prefixes differs from v1.4: %x vs %x", h110, h14)
	}
}

// TestAllowlistHashWithAORs_Changes — non-empty aors CHANGES the
// hash. Operators who opt in get a new token.
func TestAllowlistHashWithAORs_Changes(t *testing.T) {
	methods := []sipwrite.AllowedMethod{{Method: "REGISTER"}}
	aors := []sipwrite.AllowedAOR{{AOR: "sip:alice@example.com"}}
	h14 := sipwrite.AllowlistHash("pbx:5060", methods)
	h110 := sipwrite.AllowlistHashWithAORs("pbx:5060", methods, nil, aors)
	if bytes.Equal(h14[:], h110[:]) {
		t.Fatal("v1.10 hash with aors must differ from v1.4")
	}
}

// TestAllowlistHashWithAORs_OrderInsensitive — input order of
// AORs doesn't affect the hash.
func TestAllowlistHashWithAORs_OrderInsensitive(t *testing.T) {
	methods := []sipwrite.AllowedMethod{{Method: "REGISTER"}}
	a := []sipwrite.AllowedAOR{
		{AOR: "sip:alice@example.com"},
		{AOR: "sip:bob@example.com"},
	}
	b := []sipwrite.AllowedAOR{
		{AOR: "sip:bob@example.com"},
		{AOR: "sip:alice@example.com"},
	}
	ha := sipwrite.AllowlistHashWithAORs("t", methods, nil, a)
	hb := sipwrite.AllowlistHashWithAORs("t", methods, nil, b)
	if !bytes.Equal(ha[:], hb[:]) {
		t.Fatal("hash depends on AOR input order")
	}
}

// TestAllowlistHashWithAORs_NormalizesInput — different input
// spellings of the same AOR produce the same hash (scheme +
// whitespace + host case folding).
func TestAllowlistHashWithAORs_NormalizesInput(t *testing.T) {
	methods := []sipwrite.AllowedMethod{{Method: "REGISTER"}}
	a := []sipwrite.AllowedAOR{{AOR: "  SIP:alice@EXAMPLE.com  "}}
	b := []sipwrite.AllowedAOR{{AOR: "alice@example.com"}}
	ha := sipwrite.AllowlistHashWithAORs("t", methods, nil, a)
	hb := sipwrite.AllowlistHashWithAORs("t", methods, nil, b)
	if !bytes.Equal(ha[:], hb[:]) {
		t.Fatal("canonicalisation of AOR input not equivalent")
	}
}

// TestAllowlistHashWithAORs_PrefixAndAORsCombine — when both
// prefixes AND aors are set, both contribute to the hash
// independently.
func TestAllowlistHashWithAORs_PrefixAndAORsCombine(t *testing.T) {
	methods := []sipwrite.AllowedMethod{{Method: "INVITE"}, {Method: "REGISTER"}}
	prefixes := []sipwrite.AllowedToURIPrefix{{Prefix: "+34"}}
	aors := []sipwrite.AllowedAOR{{AOR: "sip:alice@example.com"}}
	// Different combinations must produce different hashes.
	hAll := sipwrite.AllowlistHashWithAORs("t", methods, prefixes, aors)
	hPrefixOnly := sipwrite.AllowlistHashWithAORs("t", methods, prefixes, nil)
	hAORsOnly := sipwrite.AllowlistHashWithAORs("t", methods, nil, aors)
	if bytes.Equal(hAll[:], hPrefixOnly[:]) {
		t.Fatal("hash(methods+prefix+aors) == hash(methods+prefix): aors not mixed in")
	}
	if bytes.Equal(hAll[:], hAORsOnly[:]) {
		t.Fatal("hash(methods+prefix+aors) == hash(methods+aors): prefix not mixed in")
	}
}

// TestSessionMutationWithAORs_Shape — sanity check on the
// confirm.Mutation produced by the v1.10 factory.
func TestSessionMutationWithAORs_Shape(t *testing.T) {
	methods := []sipwrite.AllowedMethod{{Method: "REGISTER"}}
	aors := []sipwrite.AllowedAOR{{AOR: "sip:alice@example.com"}}
	mut := sipwrite.SessionMutationWithAORs("pbx:5060", methods, nil, aors)
	if mut.Protocol != "sip" {
		t.Errorf("Protocol = %q, want sip", mut.Protocol)
	}
	if mut.Operation != "proxy_session" {
		t.Errorf("Operation = %q, want proxy_session", mut.Operation)
	}
	if mut.Target != "pbx:5060" {
		t.Errorf("Target = %q, want pbx:5060", mut.Target)
	}
	// PayloadHash should match the hash function directly.
	want := sipwrite.AllowlistHashWithAORs("pbx:5060", methods, nil, aors)
	if !bytes.Equal(mut.PayloadHash[:], want[:]) {
		t.Error("PayloadHash does not match AllowlistHashWithAORs output")
	}
}

// ---- End-to-end gate with AOR allowlist active --------------

// driveSessionWithAORs authorises a WriteGatedHandler with the
// v1.10 AOR allowlist active and returns the client-side conn +
// upstream recorder.
func driveSessionWithAORs(t *testing.T, methods []sipwrite.AllowedMethod, aors []sipwrite.AllowedAOR) (net.Conn, *upstreamRecorder) {
	t.Helper()
	target := "sip-server.test:5060"
	h := &sipwrite.WriteGatedHandler{
		Target:      target,
		Allowed:     methods,
		AllowedAORs: aors,
		Deriver:     &fakeDeriver{key: []byte(testDeriverKey)},
		Auditor:     &fakeAuditor{},
	}
	mut := sipwrite.SessionMutationWithAORs(target, methods, nil, aors)
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

// TestRouting_REGISTERAllowedByAOR — REGISTER whose To: header
// exactly matches an allowlist entry passes.
func TestRouting_REGISTERAllowedByAOR(t *testing.T) {
	client, upstream := driveSessionWithAORs(t,
		[]sipwrite.AllowedMethod{{Method: "REGISTER"}},
		[]sipwrite.AllowedAOR{
			{AOR: "sip:alice@pbx.internal"},
			{AOR: "sip:bob@pbx.internal"},
		},
	)
	req := "REGISTER sip:pbx.internal SIP/2.0\r\n" +
		"Via: SIP/2.0/TCP c;branch=z9hG4bK.1\r\n" +
		"From: <sip:alice@pbx.internal>;tag=x\r\n" +
		"To: <sip:alice@pbx.internal>\r\n" +
		"Call-ID: c1\r\n" +
		"CSeq: 1 REGISTER\r\n" +
		"Contact: <sip:alice@192.168.1.5:5060>\r\n" +
		"Expires: 3600\r\n" +
		"Content-Length: 0\r\n\r\n"
	_, _ = io.WriteString(client, req)
	seen := upstream.seen(t, 80)
	if !strings.HasPrefix(seen, "REGISTER sip:pbx.internal SIP/2.0") {
		t.Fatalf("upstream did not see allowed REGISTER:\n%s", seen)
	}
}

// TestRouting_REGISTERBlockedByAOR — REGISTER whose AoR is NOT
// in the allowlist is refused with 403 + X-Elsereno-Gate-Reason.
// This is the registration-hijack mitigation working.
func TestRouting_REGISTERBlockedByAOR(t *testing.T) {
	client, upstream := driveSessionWithAORs(t,
		[]sipwrite.AllowedMethod{{Method: "REGISTER"}},
		[]sipwrite.AllowedAOR{
			{AOR: "sip:alice@pbx.internal"},
		},
	)
	// Attacker has alice's creds but tries to register admin's AOR.
	req := "REGISTER sip:pbx.internal SIP/2.0\r\n" +
		"Via: SIP/2.0/TCP c;branch=z9hG4bK.1\r\n" +
		"From: <sip:alice@pbx.internal>;tag=x\r\n" +
		"To: <sip:admin@pbx.internal>\r\n" +
		"Call-ID: c1\r\n" +
		"CSeq: 1 REGISTER\r\n" +
		"Contact: <sip:attacker@10.9.8.7:5060>\r\n" +
		"Expires: 3600\r\n" +
		"Content-Length: 0\r\n\r\n"
	_, _ = io.WriteString(client, req)
	resp := readSIPResponse(t, client)
	if !strings.HasPrefix(resp, "SIP/2.0 403 Forbidden") { //nolint:misspell // RFC 3261 §21.4 canonical spelling
		t.Fatalf("expected 403, got:\n%s", resp)
	}
	if !strings.Contains(resp, "X-Elsereno-Gate-Reason:") {
		t.Errorf("refusal should include X-Elsereno-Gate-Reason: %s", resp)
	}
	if !strings.Contains(resp, "AOR not in session allowlist") {
		t.Errorf("X-Elsereno-Gate-Reason should identify the AOR gate: %s", resp)
	}
	time.Sleep(50 * time.Millisecond)
	if snap := upstream.snapshot(); len(snap) != 0 {
		t.Fatalf("upstream saw bytes for a blocked REGISTER: %q", snap)
	}
}

// TestRouting_EmptyAORListFallsBackToV19 — empty aors → v1.9
// (or v1.4) behaviour: REGISTER passes as long as REGISTER is
// in the method allowlist.
func TestRouting_EmptyAORListFallsBackToV19(t *testing.T) {
	client, upstream := driveSessionWithAORs(t,
		[]sipwrite.AllowedMethod{{Method: "REGISTER"}},
		nil, // no AOR gating
	)
	req := "REGISTER sip:pbx.internal SIP/2.0\r\n" +
		"Via: SIP/2.0/TCP c;branch=z9hG4bK.1\r\n" +
		"From: <sip:anyone@pbx.internal>;tag=x\r\n" +
		"To: <sip:anyone@pbx.internal>\r\n" +
		"Call-ID: c1\r\n" +
		"CSeq: 1 REGISTER\r\n" +
		"Contact: <sip:anyone@192.168.1.99:5060>\r\n" +
		"Content-Length: 0\r\n\r\n"
	_, _ = io.WriteString(client, req)
	seen := upstream.seen(t, 60)
	if !strings.HasPrefix(seen, "REGISTER sip:pbx.internal SIP/2.0") {
		t.Fatalf("v1.9/v1.4 fallback: upstream should have seen the REGISTER:\n%s", seen)
	}
}

// TestRouting_INVITENotAffectedByAORAllowlist — AOR list gates
// REGISTER only. INVITE with a different To: than any AOR entry
// still passes (the AOR gate doesn't touch the INVITE path).
func TestRouting_INVITENotAffectedByAORAllowlist(t *testing.T) {
	client, upstream := driveSessionWithAORs(t,
		[]sipwrite.AllowedMethod{{Method: "INVITE"}},
		[]sipwrite.AllowedAOR{{AOR: "sip:alice@pbx.internal"}},
	)
	// INVITE to a destination that has nothing to do with the
	// AOR entry — should STILL pass because AOR list gates REGISTER.
	req := "INVITE sip:+34600123@carrier SIP/2.0\r\n" +
		"Via: SIP/2.0/TCP c;branch=z9hG4bK.1\r\n" +
		"From: <sip:a@c>;tag=x\r\n" +
		"To: <sip:+34600123@carrier>\r\n" +
		"Call-ID: c1\r\n" +
		"CSeq: 1 INVITE\r\n" +
		"Content-Length: 0\r\n\r\n"
	_, _ = io.WriteString(client, req)
	seen := upstream.seen(t, 60)
	if !strings.HasPrefix(seen, "INVITE sip:+34600123@carrier SIP/2.0") {
		t.Fatalf("INVITE should have passed (AOR list only gates REGISTER):\n%s", seen)
	}
}

// TestRouting_REGISTERCanonicaliseOnCompare — the wire To: header
// uses `<sips:Alice@PBX.Internal>` but the operator allowlisted
// `sip:alice@pbx.internal`. Canonicalisation folds scheme + host
// case, so the match should succeed.
func TestRouting_REGISTERCanonicaliseOnCompare(t *testing.T) {
	client, upstream := driveSessionWithAORs(t,
		[]sipwrite.AllowedMethod{{Method: "REGISTER"}},
		[]sipwrite.AllowedAOR{{AOR: "sip:alice@pbx.internal"}},
	)
	// Wire uses SIPS + uppercase host.
	req := "REGISTER sip:pbx.internal SIP/2.0\r\n" +
		"Via: SIP/2.0/TCP c;branch=z9hG4bK.1\r\n" +
		"From: <sips:alice@PBX.Internal>;tag=x\r\n" +
		"To: <sips:alice@PBX.Internal>\r\n" +
		"Call-ID: c1\r\n" +
		"CSeq: 1 REGISTER\r\n" +
		"Contact: <sips:alice@192.168.1.5:5061>\r\n" +
		"Content-Length: 0\r\n\r\n"
	_, _ = io.WriteString(client, req)
	seen := upstream.seen(t, 80)
	if !strings.HasPrefix(seen, "REGISTER sip:pbx.internal SIP/2.0") {
		t.Fatalf("canonicalised match should have let this REGISTER pass:\n%s", seen)
	}
}
