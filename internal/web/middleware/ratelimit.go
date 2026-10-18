package middleware

import (
	"crypto/sha256"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// maxKeys caps each bucket map. A full map refuses callers it does not
// already know (429) instead of growing, so rotating keys cannot exhaust
// memory.
const maxKeys = 100_000

// RateLimiter caps requests per client IP and per auth token, the two
// limits the web config declares (rate_limit_per_min_ip,
// rate_limit_per_min_token). It is a token bucket per key, refilled at
// perMin/60 per second with a burst of perMin, so a client may spend a
// minute's budget at once and then drip. A bucket idle for a minute is
// full again, so it is forgotten then: dropping it changes nothing for
// the caller and keeps the maps small.
//
// Loopback clients are exempt from the per-IP limit (a local operator or
// a sidecar is trusted; this matches the dev-mode model), but the
// per-token limit still applies when a token is present. IPv6 clients
// are keyed by their /64, the block a single host usually controls.
// /healthz and /readyz are never limited, so a load balancer's probes
// are not throttled.
type RateLimiter struct {
	perMinIP    int
	perMinToken int

	// mu guards ips, toks, every bucket.seen and lastSweep; allow runs
	// under it end to end, so the two buckets of one request are
	// decided together.
	mu        sync.Mutex
	ips       map[string]*bucket
	toks      map[[sha256.Size]byte]*bucket
	sweep     time.Duration
	lastSweep time.Time
}

type bucket struct {
	lim  *rate.Limiter
	seen time.Time
}

// NewRateLimiter builds a limiter from the two per-minute caps. A cap
// of zero disables that dimension. A nil *RateLimiter (never built) is
// a pass-through via Wrap.
func NewRateLimiter(perMinIP, perMinToken int) *RateLimiter {
	return &RateLimiter{
		perMinIP:    perMinIP,
		perMinToken: perMinToken,
		ips:         map[string]*bucket{},
		toks:        map[[sha256.Size]byte]*bucket{},
		sweep:       time.Minute,
	}
}

// Wrap returns next guarded by the limiter. A nil limiter, or both caps
// zero, returns next unchanged.
func (rl *RateLimiter) Wrap(next http.Handler) http.Handler {
	if rl == nil || (rl.perMinIP <= 0 && rl.perMinToken <= 0) {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
			next.ServeHTTP(w, r)
			return
		}
		if !rl.allow(r) {
			w.Header().Set("Retry-After", "60")
			http.Error(w, "serve: rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// allow reports whether the request is within both applicable limits.
// The IP bucket is checked first, so a caller already over its IP cap
// never creates or touches a token bucket. A token taken from the IP
// bucket is handed back if the token bucket then refuses, so a refusal
// costs the caller nothing.
func (rl *RateLimiter) allow(r *http.Request) bool {
	now := time.Now()
	ip := clientKey(r.RemoteAddr)
	tok := requestToken(r)

	rl.mu.Lock()
	defer rl.mu.Unlock()
	if now.Sub(rl.lastSweep) >= rl.sweep {
		rl.sweepLocked(now)
	}

	var held *rate.Reservation
	if rl.perMinIP > 0 && ip != "" && !isLoopback(ip) {
		b := bucketLocked(rl.ips, ip, rl.perMinIP, now)
		if b == nil {
			return false
		}
		held = b.ReserveN(now, 1)
		if !held.OK() || held.DelayFrom(now) > 0 {
			held.CancelAt(now)
			return false
		}
	}
	if rl.perMinToken > 0 && tok != "" {
		b := bucketLocked(rl.toks, sha256.Sum256([]byte(tok)), rl.perMinToken, now)
		if b == nil || !b.AllowN(now, 1) {
			if held != nil {
				held.CancelAt(now)
			}
			return false
		}
	}
	return true
}

// bucketLocked returns the limiter for key, creating it unless the map
// is full; nil means full and unknown, which the caller refuses.
func bucketLocked[K comparable](m map[K]*bucket, key K, perMin int, now time.Time) *rate.Limiter {
	b := m[key]
	if b == nil {
		if len(m) >= maxKeys {
			return nil
		}
		b = &bucket{lim: rate.NewLimiter(rate.Limit(float64(perMin)/60.0), perMin)}
		m[key] = b
	}
	b.seen = now
	return b.lim
}

// sweepLocked drops buckets idle past the sweep window. allow calls it
// at most once per window, not per request, so its cost does not grow
// with the request rate.
func (rl *RateLimiter) sweepLocked(now time.Time) {
	rl.lastSweep = now
	for k, b := range rl.ips {
		if now.Sub(b.seen) > rl.sweep {
			delete(rl.ips, k)
		}
	}
	for k, b := range rl.toks {
		if now.Sub(b.seen) > rl.sweep {
			delete(rl.toks, k)
		}
	}
}

// clientKey is the per-IP key: the host part of RemoteAddr, with IPv6
// reduced to its /64. X-Forwarded-For is ignored on purpose: serve is
// loopback by default and, behind a trusted proxy, spoofed forwarding
// headers must not let a client dodge the limit.
func clientKey(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = strings.TrimSpace(remoteAddr)
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() != nil || ip.IsLoopback() {
		return host
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

// requestToken keys the per-token limit by the bearer token or, in dev
// mode, the X-Operator header. It is not verified here: rate limiting
// only needs a stable key per caller. allow stores only its SHA-256, so
// a token never sits in the limiter's maps.
func requestToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
	}
	return strings.TrimSpace(r.Header.Get("X-Operator"))
}

func isLoopback(host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return strings.EqualFold(host, "localhost")
}
