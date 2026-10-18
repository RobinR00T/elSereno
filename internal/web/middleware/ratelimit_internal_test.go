package middleware

import (
	"context"
	"crypto/sha256"
	"net/http"
	"testing"
	"time"
)

func req(remote, operator string) *http.Request {
	r, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://127.0.0.1/api/v1/scans", nil)
	r.RemoteAddr = remote
	if operator != "" {
		r.Header.Set("X-Operator", operator)
	}
	return r
}

// TestAllow_IPRefusalCreatesNoTokenBucket: a caller over its IP cap that
// rotates tokens cannot grow the token map (audit H1, PITF-100).
func TestAllow_IPRefusalCreatesNoTokenBucket(t *testing.T) {
	rl := NewRateLimiter(1, 100)
	if !rl.allow(req("10.0.0.9:1", "tok-0")) {
		t.Fatal("first request refused")
	}
	for i := 1; i <= 50; i++ {
		if rl.allow(req("10.0.0.9:1", "tok-"+string(rune('a'+i%26))+string(rune('a'+i/26)))) {
			t.Fatalf("request %d over the IP cap allowed", i)
		}
	}
	if n := len(rl.toks); n != 1 {
		t.Fatalf("token buckets = %d, want 1 (only the first, allowed request)", n)
	}
}

// TestAllow_TokenRefusalHandsBackIP: a request the token bucket refuses
// does not spend the IP bucket.
func TestAllow_TokenRefusalHandsBackIP(t *testing.T) {
	rl := NewRateLimiter(2, 1)
	if !rl.allow(req("10.0.0.9:1", "alice")) {
		t.Fatal("first request refused")
	}
	if rl.allow(req("10.0.0.9:1", "alice")) {
		t.Fatal("second request with the same token allowed")
	}
	// The IP bucket still holds one token: another operator gets in.
	if !rl.allow(req("10.0.0.9:1", "bob")) {
		t.Fatal("token refusal spent the IP bucket")
	}
}

// TestAllow_SweepIsPeriodic: the sweep runs at most once per window and
// drops idle buckets when it does.
func TestAllow_SweepIsPeriodic(t *testing.T) {
	rl := NewRateLimiter(100, 0)
	rl.allow(req("10.0.0.1:1", ""))
	first := rl.lastSweep
	rl.allow(req("10.0.0.2:1", ""))
	if !rl.lastSweep.Equal(first) {
		t.Fatal("sweep ran on the second request inside the window")
	}
	// Age every bucket and the last sweep past the window.
	old := time.Now().Add(-2 * rl.sweep)
	for _, b := range rl.ips {
		b.seen = old
	}
	rl.lastSweep = old
	rl.allow(req("10.0.0.3:1", ""))
	if len(rl.ips) != 1 {
		t.Fatalf("buckets after sweep = %d, want 1 (only the new caller)", len(rl.ips))
	}
}

// TestAllow_MapCap: with a full map, an unknown key is refused and a
// known one still served.
func TestAllow_MapCap(t *testing.T) {
	rl := NewRateLimiter(0, 100)
	for i := 0; i < maxKeys; i++ {
		var k [sha256.Size]byte
		k[0], k[1], k[2] = byte(i), byte(i>>8), byte(i>>16)
		rl.toks[k] = &bucket{lim: nil, seen: time.Now()}
	}
	rl.lastSweep = time.Now()
	if rl.allow(req("127.0.0.1:1", "newcomer")) {
		t.Fatal("unknown key admitted into a full map")
	}
	if len(rl.toks) != maxKeys {
		t.Fatalf("map grew past the cap: %d", len(rl.toks))
	}
}

// TestClientKey: IPv4 and loopback stay whole, IPv6 is grouped by /64.
func TestClientKey(t *testing.T) {
	cases := map[string]string{
		"10.0.0.9:1":                 "10.0.0.9",
		"[::1]:1":                    "::1",
		"[2001:db8:1:2:aaaa::1]:443": "2001:db8:1:2::/64",
		"[2001:db8:1:2:bbbb::9]:443": "2001:db8:1:2::/64",
		"[2001:db8:1:3::1]:443":      "2001:db8:1:3::/64",
		"[::ffff:192.0.2.7]:80":      "::ffff:192.0.2.7",
		"not-an-addr":                "not-an-addr",
	}
	for in, want := range cases {
		if got := clientKey(in); got != want {
			t.Errorf("clientKey(%q) = %q, want %q", in, got, want)
		}
	}
}
