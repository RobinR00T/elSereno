//go:build offensive

package sip

import (
	"bytes"
	"io"
	"testing"
)

// FuzzForward drives the full request path: the framing loop reads
// request lines + headers + body from target-controlled bytes, applies
// the method + per-method gates, and forwards or refuses. It must never
// panic. Outputs are discarded; the handler carries every gate slice so
// the invite/AOR/from-domain paths are all reachable. No Auditor/Deriver
// is needed (forward does not touch them). parseContentLength caps the
// body at 1 MiB, so a hostile Content-Length cannot OOM the fuzzer.
func FuzzForward(f *testing.F) {
	f.Add([]byte("INVITE sip:bob@example.com SIP/2.0\r\nTo: <sip:bob@example.com>\r\nFrom: <sip:a@x.com>\r\nContent-Length: 0\r\n\r\n"))
	f.Add([]byte("REGISTER sip:example.com SIP/2.0\r\nTo: <sip:bob@example.com>\r\nContent-Length: 3\r\n\r\nabc"))
	f.Add([]byte("OPTIONS sip:x SIP/2.0\r\nContent-Length: 999999\r\n\r\n"))
	f.Add([]byte("SIP/2.0 200 OK\r\n\r\n"))
	f.Add([]byte("GARBAGE\r\n\r\n"))
	f.Add([]byte(""))
	f.Fuzz(func(_ *testing.T, b []byte) {
		h := &WriteGatedHandler{
			Target:               "sip:pbx.example.com",
			Allowed:              []AllowedMethod{{Method: "INVITE"}, {Method: "REGISTER"}},
			AllowedToURIPrefixes: []AllowedToURIPrefix{{Prefix: "sip:bob@"}},
			AllowedAORs:          []AllowedAOR{{AOR: "sip:bob@example.com"}},
			AllowedFromDomains:   []AllowedFromDomain{{Domain: "x.com"}},
		}
		_ = h.forward(bytes.NewReader(b), io.Discard, io.Discard)
	})
}

// The write-gate proxy parses target-controlled SIP request lines and
// headers. None of the parse/extract/canonicalise helpers may panic on
// malformed input, however hostile.

func FuzzParseMethod(f *testing.F) {
	f.Add("INVITE sip:bob@example.com SIP/2.0")
	f.Add("REGISTER sip:example.com SIP/2.0")
	f.Add("")
	f.Add("   ")
	f.Add("NOSPACES")
	f.Add("a b c d e")
	f.Fuzz(func(_ *testing.T, s string) { _, _ = parseMethod(s) })
}

func FuzzParseContentLength(f *testing.F) {
	f.Add("0")
	f.Add("42")
	f.Add("-1")
	f.Add("")
	f.Add("   7  ")
	f.Add("12x")
	f.Add("999999999999999999999999999999")
	f.Fuzz(func(_ *testing.T, s string) { _, _ = parseContentLength(s) })
}

func FuzzExtractToURIUser(f *testing.F) {
	f.Add("<sip:bob@example.com>")
	f.Add("sip:bob@example.com;tag=99")
	f.Add("\"Bob\" <sip:bob@example.com>")
	f.Add("")
	f.Add("<sip:>")
	f.Add("<sip:@>")
	f.Fuzz(func(_ *testing.T, s string) { _ = extractToURIUser(s) })
}

func FuzzExtractToURIFull(f *testing.F) {
	f.Add("<sip:bob@example.com>")
	f.Add("sip:bob@example.com")
	f.Add("")
	f.Add("<>")
	f.Fuzz(func(_ *testing.T, s string) { _ = extractToURIFull(s) })
}

func FuzzExtractFromURIFull(f *testing.F) {
	f.Add("\"Alice\" <sip:alice@example.com>;tag=1")
	f.Add("sip:alice@example.com")
	f.Add("")
	f.Add("<sip:@example.com>")
	f.Fuzz(func(_ *testing.T, s string) { _ = extractFromURIFull(s) })
}

func FuzzCanonicaliseAOR(f *testing.F) {
	f.Add("sip:bob@example.com")
	f.Add("BOB@Example.COM")
	f.Add("<sip:bob@example.com;transport=tcp>")
	f.Add("")
	f.Add("@")
	f.Fuzz(func(_ *testing.T, s string) { _ = canonicaliseAOR(s) })
}

func FuzzCanonicaliseFromDomain(f *testing.F) {
	f.Add("sip:alice@Example.COM")
	f.Add("@host")
	f.Add("")
	f.Add("<sip:a@b>")
	f.Fuzz(func(_ *testing.T, s string) { _ = canonicaliseFromDomain(s) })
}
