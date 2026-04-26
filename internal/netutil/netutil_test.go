package netutil_test

import (
	"errors"
	"testing"

	"local/elsereno/internal/netutil"
)

func TestIsLoopbackHostPort(t *testing.T) {
	cases := map[string]bool{
		// Empty → treated as default loopback.
		"": true,

		// Hostname forms.
		"localhost":      true,
		"localhost:8787": true,

		// IPv4 loopback (127/8).
		"127.0.0.1:8787":         true,
		"127.0.0.5:1234":         true,
		"127.255.255.255:443":    true,
		"127.0.0.1":              true,  // bare IP without port
		"127.0.0.1:8787:invalid": false, // double colons — ParseAddrPort rejects

		// IPv6 loopback shortform.
		"[::1]:8787": true,
		"[::1]:7547": true,
		"[::1]:0":    true,

		// IPv6 loopback longform.
		"[0:0:0:0:0:0:0:1]:8787": true,
		"[0:0:0:0:0:0:0:1]:443":  true,

		// IPv6 loopback with zone specifier.
		"[::1%lo0]:8787": true,
		"[::1%lo]:443":   true,

		// IPv6 unspecified (::, any-interface bind) — NOT loopback.
		"[::]:8787":            false,
		"[::]:443":             false,
		"[0:0:0:0:0:0:0:0]:80": false,

		// Non-loopback IPv4.
		"8.8.8.8:53":     false,
		"10.0.0.1:8787":  false,
		"192.168.1.1:80": false,
		"0.0.0.0:8787":   false, // any-interface, NOT loopback

		// Non-loopback IPv6.
		"[2001:db8::1]:443": false,
		"[fe80::1]:8787":    false,

		// Garbage.
		"::1:8787":              false, // missing brackets — not a parseable v6 host:port
		"localhost:":            false, // empty port after colon
		"i-am-not-an-address":   false,
		"random:thing:withport": false,
	}
	for input, want := range cases {
		t.Run(input, func(t *testing.T) {
			got := netutil.IsLoopbackHostPort(input)
			if got != want {
				t.Errorf("IsLoopbackHostPort(%q) = %v, want %v", input, got, want)
			}
		})
	}
}

func TestCanonicalHostPort(t *testing.T) {
	cases := map[string]string{
		// IPv4 — unchanged.
		"127.0.0.1:7547": "127.0.0.1:7547",
		"8.8.8.8:53":     "8.8.8.8:53",

		// IPv6 — already canonical.
		"[::1]:7547":        "[::1]:7547",
		"[2001:db8::1]:443": "[2001:db8::1]:443",

		// IPv6 longform → shortform.
		"[0:0:0:0:0:0:0:1]:7547":                        "[::1]:7547",
		"[2001:0db8:0000:0000:0000:0000:0000:0001]:443": "[2001:db8::1]:443",

		// IPv6 uppercase → lowercase.
		"[2001:DB8::1]:443": "[2001:db8::1]:443",
		"[FE80::ABCD]:8787": "[fe80::abcd]:8787",

		// Hostname forms — passed through unchanged.
		"localhost:8787":  "localhost:8787",
		"example.com:443": "example.com:443",
	}
	for input, want := range cases {
		t.Run(input, func(t *testing.T) {
			got, err := netutil.CanonicalHostPort(input)
			if err != nil {
				t.Fatalf("CanonicalHostPort(%q) error: %v", input, err)
			}
			if got != want {
				t.Errorf("CanonicalHostPort(%q) = %q, want %q", input, got, want)
			}
		})
	}
}

func TestCanonicalHostPort_EmptyReturnsSentinel(t *testing.T) {
	_, err := netutil.CanonicalHostPort("")
	if !errors.Is(err, netutil.ErrEmptyHostPort) {
		t.Fatalf("got %v, want ErrEmptyHostPort", err)
	}
}

func TestParseAddrPort_EmptyReturnsSentinel(t *testing.T) {
	_, err := netutil.ParseAddrPort("")
	if !errors.Is(err, netutil.ErrEmptyHostPort) {
		t.Fatalf("got %v, want ErrEmptyHostPort", err)
	}
}

func TestParseAddrPort_HappyPath(t *testing.T) {
	cases := []string{
		"127.0.0.1:7547",
		"[::1]:7547",
		"[2001:db8::1]:443",
		"[fe80::1%lo0]:8787",
	}
	for _, s := range cases {
		t.Run(s, func(t *testing.T) {
			ap, err := netutil.ParseAddrPort(s)
			if err != nil {
				t.Fatalf("ParseAddrPort(%q) error: %v", s, err)
			}
			if !ap.IsValid() {
				t.Errorf("ParseAddrPort(%q) returned invalid AddrPort", s)
			}
		})
	}
}
