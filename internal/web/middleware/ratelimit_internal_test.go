package middleware

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"testing"
	"time"

	"golang.org/x/time/rate"
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

// fillTokens fills the token map with maxKeys made-up keys.
func fillTokens(rl *RateLimiter, now time.Time) {
	for i := 0; i < maxKeys; i++ {
		var k [sha256.Size]byte
		k[0], k[1], k[2] = byte(i), byte(i>>8), byte(i>>16)
		k[3] = 0xff // never the hash of a real test token
		rl.toks[k] = &bucket{lim: rate.NewLimiter(1, 1), seen: now}
	}
}

// TestAllow_FullTokenMapFailsOpen: 100 000 made-up tokens fill the map,
// and a new operator is still served instead of locked out (PITF-100
// audit: refusing let anyone without credentials deny every newcomer).
// A token already in the map keeps its limit, and the map does not grow.
func TestAllow_FullTokenMapFailsOpen(t *testing.T) {
	rl := NewRateLimiter(0, 1)
	now := time.Now()
	rl.now = func() time.Time { return now }
	if !rl.allow(req("127.0.0.1:1", "alice")) {
		t.Fatal("alice's first request refused")
	}
	fillTokens(rl, now)
	rl.lastSweep = now
	for i := 0; i < 3; i++ {
		if !rl.allow(req("127.0.0.1:1", "newcomer")) {
			t.Fatalf("newcomer request %d refused by a full token map", i)
		}
	}
	if rl.allow(req("127.0.0.1:1", "alice")) {
		t.Fatal("alice, already in the map, lost her token limit")
	}
	if len(rl.toks) != maxKeys+1 {
		t.Fatalf("token map = %d entries, want %d (no growth past the cap)", len(rl.toks), maxKeys+1)
	}
}

// TestAllow_FullIPMapFailsOpen: the same for the IP map (an attacker
// with a /48 has 65 536 /64s). A new address is served; a known one keeps
// its limit.
func TestAllow_FullIPMapFailsOpen(t *testing.T) {
	rl := NewRateLimiter(1, 0)
	now := time.Now()
	rl.now = func() time.Time { return now }
	if !rl.allow(req("10.0.0.9:1", "")) {
		t.Fatal("first request refused")
	}
	for i := 0; len(rl.ips) < maxKeys; i++ {
		rl.ips[fmt.Sprintf("2001:db8:%x:%x::/64", i>>16, i&0xffff)] = &bucket{lim: rate.NewLimiter(1, 1), seen: now}
	}
	rl.lastSweep = now
	if !rl.allow(req("10.0.0.10:1", "")) {
		t.Fatal("new address refused by a full IP map")
	}
	if rl.allow(req("10.0.0.9:1", "")) {
		t.Fatal("known address lost its limit")
	}
	if len(rl.ips) != maxKeys {
		t.Fatalf("IP map = %d entries, want %d", len(rl.ips), maxKeys)
	}
}

// TestAllow_Refill: a bucket refills at perMin/60 per second. With a cap
// of 60 one request comes back each second, and a whole minute refills
// the burst, not more.
func TestAllow_Refill(t *testing.T) {
	rl := NewRateLimiter(60, 0)
	now := time.Now()
	rl.now = func() time.Time { return now }
	for i := 0; i < 60; i++ {
		if !rl.allow(req("10.0.0.9:1", "")) {
			t.Fatalf("request %d of the burst refused", i)
		}
	}
	if rl.allow(req("10.0.0.9:1", "")) {
		t.Fatal("request 61 allowed with an empty bucket")
	}
	now = now.Add(999 * time.Millisecond)
	if rl.allow(req("10.0.0.9:1", "")) {
		t.Fatal("allowed before a full second refilled one token")
	}
	now = now.Add(time.Millisecond)
	if !rl.allow(req("10.0.0.9:1", "")) {
		t.Fatal("one second did not refill one token")
	}
	if rl.allow(req("10.0.0.9:1", "")) {
		t.Fatal("one second refilled more than one token")
	}
	// Five minutes idle: the bucket is full again (60), never more.
	// Keep the sweep from dropping it so the cap itself is what is tested.
	now = now.Add(5 * time.Minute)
	rl.lastSweep = now
	for _, b := range rl.ips {
		b.seen = now
	}
	n := 0
	for rl.allow(req("10.0.0.9:1", "")) {
		n++
		if n > 1000 {
			break
		}
	}
	if n != 60 {
		t.Fatalf("after a long idle the burst was %d, want 60", n)
	}
}

// TestAllow_NoTokenNoBucket: a request without a token never creates a
// token bucket, so tokenless traffic cannot fill the token map.
func TestAllow_NoTokenNoBucket(t *testing.T) {
	rl := NewRateLimiter(100, 100)
	for i := 0; i < 10; i++ {
		rl.allow(req("10.0.0.9:1", ""))
	}
	if len(rl.toks) != 0 {
		t.Fatalf("token buckets = %d, want 0", len(rl.toks))
	}
}

// TestAllow_ZeroOrNegativeCapIsOff: a cap of zero or below disables
// that dimension, it does not refuse everything.
func TestAllow_ZeroOrNegativeCapIsOff(t *testing.T) {
	for _, caps := range [][2]int{{0, 0}, {-1, -5}} {
		rl := NewRateLimiter(caps[0], caps[1])
		for i := 0; i < 500; i++ {
			if !rl.allow(req("10.0.0.9:1", "alice")) {
				t.Fatalf("caps %v: request %d refused", caps, i)
			}
		}
		if len(rl.ips)+len(rl.toks) != 0 {
			t.Fatalf("caps %v created buckets", caps)
		}
	}
}

// TestAllow_SweepDropsIdleTokens: the sweep empties the token map too,
// so tokens seen once do not hold room for ever.
func TestAllow_SweepDropsIdleTokens(t *testing.T) {
	rl := NewRateLimiter(0, 100)
	now := time.Now()
	rl.now = func() time.Time { return now }
	for i := 0; i < 5; i++ {
		rl.allow(req("127.0.0.1:1", fmt.Sprintf("tok-%d", i)))
	}
	now = now.Add(2 * rl.sweep)
	rl.allow(req("127.0.0.1:1", "fresh"))
	if len(rl.toks) != 1 {
		t.Fatalf("token buckets after sweep = %d, want 1 (only the fresh one)", len(rl.toks))
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
