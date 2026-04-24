//go:build offensive

package sip_test

import (
	"bytes"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"local/elsereno/offensive/confirm"
	sipwrite "local/elsereno/offensive/write/sip"
)

// ---- Hash ladder: rich variant degrades to v1.10 / v1.9 / v1.4

func TestAllowlistHashWithFromDomains_EmptyMatchesV110(t *testing.T) {
	methods := []sipwrite.AllowedMethod{{Method: "INVITE"}, {Method: "REGISTER"}}
	aors := []sipwrite.AllowedAOR{{AOR: "sip:alice@pbx.internal"}}
	h110 := sipwrite.AllowlistHashWithAORs("pbx:5060", methods, nil, aors)
	h112 := sipwrite.AllowlistHashWithFromDomains("pbx:5060", methods, nil, aors, nil)
	if !bytes.Equal(h110[:], h112[:]) {
		t.Fatalf("v1.12 hash with empty from-domains differs from v1.10: %x vs %x", h112, h110)
	}
}

func TestAllowlistHashWithFromDomains_EmptyAllMatchesV14(t *testing.T) {
	methods := []sipwrite.AllowedMethod{{Method: "INVITE"}}
	h14 := sipwrite.AllowlistHash("pbx:5060", methods)
	h112 := sipwrite.AllowlistHashWithFromDomains("pbx:5060", methods, nil, nil, nil)
	if !bytes.Equal(h14[:], h112[:]) {
		t.Fatalf("v1.12 hash with empty prefixes+aors+from-domains differs from v1.4: %x vs %x", h112, h14)
	}
}

func TestAllowlistHashWithFromDomains_NonEmptyChangesHash(t *testing.T) {
	methods := []sipwrite.AllowedMethod{{Method: "INVITE"}}
	h110 := sipwrite.AllowlistHashWithAORs("pbx:5060", methods, nil, nil)
	h112 := sipwrite.AllowlistHashWithFromDomains("pbx:5060", methods, nil, nil,
		[]sipwrite.AllowedFromDomain{{Domain: "internal.pbx"}})
	if bytes.Equal(h110[:], h112[:]) {
		t.Fatal("v1.12 hash with non-empty from-domains must differ from v1.10")
	}
}

func TestAllowlistHashWithFromDomains_OrderInsensitive(t *testing.T) {
	methods := []sipwrite.AllowedMethod{{Method: "INVITE"}}
	a := []sipwrite.AllowedFromDomain{
		{Domain: "internal.pbx"},
		{Domain: "voip.example.com"},
		{Domain: "trunk.gateway.com"},
	}
	b := []sipwrite.AllowedFromDomain{
		{Domain: "trunk.gateway.com"},
		{Domain: "internal.pbx"},
		{Domain: "voip.example.com"},
	}
	h1 := sipwrite.AllowlistHashWithFromDomains("pbx:5060", methods, nil, nil, a)
	h2 := sipwrite.AllowlistHashWithFromDomains("pbx:5060", methods, nil, nil, b)
	if !bytes.Equal(h1[:], h2[:]) {
		t.Fatal("hash depends on from-domain input order")
	}
}

// TestAllowlistHashWithFromDomains_CaseInsensitiveCanonical —
// host names are case-insensitive per RFC 3261 §19.1.1, so
// operator entries in mixed case must produce the same hash.
func TestAllowlistHashWithFromDomains_CaseInsensitiveCanonical(t *testing.T) {
	methods := []sipwrite.AllowedMethod{{Method: "INVITE"}}
	a := []sipwrite.AllowedFromDomain{{Domain: "INTERNAL.PBX"}}
	b := []sipwrite.AllowedFromDomain{{Domain: "internal.pbx"}}
	h1 := sipwrite.AllowlistHashWithFromDomains("pbx:5060", methods, nil, nil, a)
	h2 := sipwrite.AllowlistHashWithFromDomains("pbx:5060", methods, nil, nil, b)
	if !bytes.Equal(h1[:], h2[:]) {
		t.Fatalf("case-insensitive canonicalisation missing: %x vs %x", h1, h2)
	}
}

// ---- E2E gate tests -----------------------------------------

// fakeDeriverDom / fakeAuditorDom mirror the interfaces used by
// the other SIP tests (see gatedproxy_test.go).
type fakeDeriverDom struct{ key []byte }

func (f *fakeDeriverDom) Derive(_ string, out []byte) error {
	copy(out, f.key)
	return nil
}

type fakeAuditorDom struct{}

func (fakeAuditorDom) Record(_ context.Context, _ confirm.AuditEvent) error { return nil }

const testDeriverKeyDom = "unit-test-derive-key-dom-00-----"

// driveSIPFromDomainSession boots a gated handler with the given
// methods + from-domain allowlist, returns the client net.Conn +
// upstream byte recorder (race-safe, mirrors gatedproxy_test.go
// pattern).
func driveSIPFromDomainSession(t *testing.T, methods []sipwrite.AllowedMethod, fromDomains []sipwrite.AllowedFromDomain) (net.Conn, *upstreamRecorder) {
	t.Helper()
	target := "pbx.test:5060"
	h := &sipwrite.WriteGatedHandler{
		Target:             target,
		Allowed:            methods,
		AllowedFromDomains: fromDomains,
		Deriver:            &fakeDeriverDom{key: []byte(testDeriverKeyDom)},
		Auditor:            &fakeAuditorDom{},
	}
	mut := sipwrite.SessionMutationWithFromDomains(target, methods, nil, nil, fromDomains)
	tok, err := confirm.ExpectedToken(mut, &fakeDeriverDom{key: []byte(testDeriverKeyDom)})
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
	clientPipe, handlerSide := net.Pipe()
	upstreamReaderSide, upstreamWriterSide := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = clientPipe.Close()
		_ = handlerSide.Close()
		_ = upstreamReaderSide.Close()
		_ = upstreamWriterSide.Close()
	})
	recorder := &upstreamRecorder{done: make(chan struct{})}
	go recorder.run(upstreamReaderSide)
	go func() { _ = h.Handle(ctx, handlerSide, upstreamWriterSide) }()
	return clientPipe, recorder
}

func sipInvite(from, to string) string {
	return strings.Join([]string{
		"INVITE sip:" + to + " SIP/2.0",
		"Via: SIP/2.0/UDP client.test:5060;branch=z9hG4bK1",
		"From: \"Alice\" <sip:" + from + ">;tag=abc",
		"To: <sip:" + to + ">",
		"Call-ID: call-1@client.test",
		"CSeq: 1 INVITE",
		"Max-Forwards: 70",
		"Content-Length: 0",
		"",
		"",
	}, "\r\n")
}

// TestGateFromDomain_AllowedPasses — From domain matches the
// allowlist → INVITE forwards upstream.
func TestGateFromDomain_AllowedPasses(t *testing.T) {
	methods := []sipwrite.AllowedMethod{{Method: "INVITE"}}
	fromDomains := []sipwrite.AllowedFromDomain{{Domain: "internal.pbx"}}
	client, upstreamBuf := driveSIPFromDomainSession(t, methods, fromDomains)

	msg := sipInvite("alice@internal.pbx", "bob@internal.pbx")
	_, _ = client.Write([]byte(msg))

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if len(upstreamBuf.snapshot()) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(upstreamBuf.snapshot()) == 0 {
		t.Fatal("upstream saw nothing for allowed From domain")
	}
}

// TestGateFromDomain_ForbiddenRefuses — From domain NOT in the
// allowlist → 403 Forbidden with X-Elsereno-Gate-Reason header.
func TestGateFromDomain_ForbiddenRefuses(t *testing.T) {
	methods := []sipwrite.AllowedMethod{{Method: "INVITE"}}
	fromDomains := []sipwrite.AllowedFromDomain{{Domain: "internal.pbx"}}
	client, upstreamBuf := driveSIPFromDomainSession(t, methods, fromDomains)

	msg := sipInvite("attacker@evil.external", "bob@internal.pbx")
	_, _ = client.Write([]byte(msg))

	_ = client.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	rbuf := make([]byte, 4096)
	n, err := client.Read(rbuf)
	if err != nil {
		t.Fatalf("read refusal: %v", err)
	}
	resp := string(rbuf[:n])
	if !strings.Contains(resp, "SIP/2.0 403 Forbidden") {
		t.Fatalf("expected 403 Forbidden, got:\n%s", resp)
	}
	if !strings.Contains(resp, "X-Elsereno-Gate-Reason: From domain") {
		t.Errorf("expected X-Elsereno-Gate-Reason about From domain:\n%s", resp)
	}
	time.Sleep(50 * time.Millisecond)
	if got := upstreamBuf.snapshot(); len(got) != 0 {
		t.Fatalf("upstream saw %d bytes for forbidden-From-domain INVITE", len(got))
	}
}

// TestGateFromDomain_AlwaysSafeBypasses — OPTIONS (always-safe)
// should pass regardless of From domain.
func TestGateFromDomain_AlwaysSafeBypasses(t *testing.T) {
	methods := []sipwrite.AllowedMethod{{Method: "INVITE"}}
	fromDomains := []sipwrite.AllowedFromDomain{{Domain: "internal.pbx"}}
	client, upstreamBuf := driveSIPFromDomainSession(t, methods, fromDomains)

	msg := strings.Join([]string{
		"OPTIONS sip:pbx.test SIP/2.0",
		"Via: SIP/2.0/UDP client.test:5060;branch=z9hG4bK9",
		"From: <sip:anyone@somewhere.external>;tag=xyz",
		"To: <sip:pbx.test>",
		"Call-ID: call-opt@client.test",
		"CSeq: 1 OPTIONS",
		"Max-Forwards: 70",
		"Content-Length: 0",
		"",
		"",
	}, "\r\n")
	_, _ = client.Write([]byte(msg))

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if len(upstreamBuf.snapshot()) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(upstreamBuf.snapshot()) == 0 {
		t.Fatal("OPTIONS (always-safe) should bypass from-domain gate, but upstream saw nothing")
	}
}

// TestGateFromDomain_RegisterAlsoGated — the From-domain check
// applies to REGISTER too (and to any gated method). Combines
// with AOR gate and both must pass.
func TestGateFromDomain_RegisterAlsoGated(t *testing.T) {
	methods := []sipwrite.AllowedMethod{{Method: "REGISTER"}}
	fromDomains := []sipwrite.AllowedFromDomain{{Domain: "internal.pbx"}}
	client, upstreamBuf := driveSIPFromDomainSession(t, methods, fromDomains)

	msg := strings.Join([]string{
		"REGISTER sip:pbx.test SIP/2.0",
		"Via: SIP/2.0/UDP client.test:5060;branch=z9hG4bKreg",
		"From: <sip:alice@evil.external>;tag=reg",
		"To: <sip:alice@pbx.internal>",
		"Call-ID: call-reg@client.test",
		"CSeq: 2 REGISTER",
		"Max-Forwards: 70",
		"Contact: <sip:alice@client.test>",
		"Expires: 3600",
		"Content-Length: 0",
		"",
		"",
	}, "\r\n")
	_, _ = client.Write([]byte(msg))

	_ = client.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	rbuf := make([]byte, 2048)
	n, _ := client.Read(rbuf)
	if n == 0 || !strings.Contains(string(rbuf[:n]), "403 Forbidden") {
		t.Fatalf("expected 403 for forbidden From-domain REGISTER: %q", rbuf[:n])
	}
	time.Sleep(50 * time.Millisecond)
	if got := upstreamBuf.snapshot(); len(got) != 0 {
		t.Fatalf("upstream saw %d bytes for forbidden-From REGISTER", len(got))
	}
}

// ---- canonicaliseFromDomain parser coverage via hash -------

// TestFromDomainCanonicalisation_SchemeAndBrackets — entries
// with bracketed sip: URI should canonicalise the same way as
// bare `host` entries.
func TestFromDomainCanonicalisation_SchemeAndBrackets(t *testing.T) {
	methods := []sipwrite.AllowedMethod{{Method: "INVITE"}}
	a := []sipwrite.AllowedFromDomain{{Domain: "<sip:alice@internal.pbx>"}}
	b := []sipwrite.AllowedFromDomain{{Domain: "internal.pbx"}}
	h1 := sipwrite.AllowlistHashWithFromDomains("pbx:5060", methods, nil, nil, a)
	h2 := sipwrite.AllowlistHashWithFromDomains("pbx:5060", methods, nil, nil, b)
	if !bytes.Equal(h1[:], h2[:]) {
		t.Fatal("bracketed sip: URI should canonicalise to bare host")
	}
}
