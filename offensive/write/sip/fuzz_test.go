//go:build offensive

package sip

import "testing"

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
