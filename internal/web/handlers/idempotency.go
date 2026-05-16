package handlers

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"sync"
	"time"
)

// idempotencyCache (v2.18+) is a tiny in-memory cache for
// Idempotency-Key replay. Keyed by the operator-supplied
// header value; stores the response body hash + the rendered
// response so a retry with the SAME body returns the cached
// response, and a retry with a DIFFERENT body returns a
// conflict.
//
// Scope: per-process. Multi-process serve deployments don't
// share keys (acceptable — idempotency is a UX feature, not
// a correctness guarantee; an unlucky failover may double-
// commit). Future work: back this with the audit advisory
// lock from v1.90 for cross-process consistency.
type idempotencyCache struct {
	mu      sync.Mutex
	entries map[string]idempotencyEntry
	ttl     time.Duration
	maxSize int
}

type idempotencyEntry struct {
	bodyHash   string
	statusCode int
	response   []byte
	storedAt   time.Time
}

// newIdempotencyCache returns a cache with the supplied TTL
// and max-size. Defaults applied when args are zero.
func newIdempotencyCache(ttl time.Duration, maxSize int) *idempotencyCache {
	if ttl <= 0 {
		ttl = time.Hour
	}
	if maxSize <= 0 {
		maxSize = 256
	}
	return &idempotencyCache{
		entries: make(map[string]idempotencyEntry),
		ttl:     ttl,
		maxSize: maxSize,
	}
}

// idempotencyLookupResult captures the three possible outcomes
// of a cache lookup.
type idempotencyLookupResult int

const (
	// idempotencyMiss → no entry; proceed with the request.
	idempotencyMiss idempotencyLookupResult = iota
	// idempotencyHit → entry matches body hash; replay.
	idempotencyHit
	// idempotencyConflict → entry exists but body hash
	// differs; 409 to caller.
	idempotencyConflict
)

// Lookup checks the cache. Returns (result, entry). For
// idempotencyMiss the entry is zero. Purges expired entries
// during the walk.
func (c *idempotencyCache) Lookup(key string, body []byte) (idempotencyLookupResult, idempotencyEntry) {
	if key == "" {
		return idempotencyMiss, idempotencyEntry{}
	}
	hash := hashBody(body)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.purgeExpiredLocked()
	entry, ok := c.entries[key]
	if !ok {
		return idempotencyMiss, idempotencyEntry{}
	}
	if entry.bodyHash != hash {
		return idempotencyConflict, entry
	}
	return idempotencyHit, entry
}

// Store stores a (key, body, status, response) tuple. No-op
// for empty key. Evicts the oldest entry when over maxSize.
func (c *idempotencyCache) Store(key string, body []byte, status int, response []byte) {
	if key == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= c.maxSize {
		c.evictOldestLocked()
	}
	c.entries[key] = idempotencyEntry{
		bodyHash:   hashBody(body),
		statusCode: status,
		response:   append([]byte(nil), response...),
		storedAt:   time.Now(),
	}
}

// purgeExpiredLocked drops entries older than TTL. Caller
// must hold mu.
func (c *idempotencyCache) purgeExpiredLocked() {
	cutoff := time.Now().Add(-c.ttl)
	for k, e := range c.entries {
		if e.storedAt.Before(cutoff) {
			delete(c.entries, k)
		}
	}
}

// evictOldestLocked drops the entry with the earliest
// storedAt. Caller must hold mu.
func (c *idempotencyCache) evictOldestLocked() {
	var (
		oldest    string
		oldestAt  time.Time
		hasOldest bool
	)
	for k, e := range c.entries {
		if !hasOldest || e.storedAt.Before(oldestAt) {
			oldest = k
			oldestAt = e.storedAt
			hasOldest = true
		}
	}
	if hasOldest {
		delete(c.entries, oldest)
	}
}

// hashBody returns the SHA-256 hex of the request body.
// Truncated bodies are still uniquely fingerprinted by the
// full hash (no truncation here).
func hashBody(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// Module-level default cache: 1h TTL, 256 entries. Shared by
// all import requests across the process.
var defaultIdempotencyCache = newIdempotencyCache(time.Hour, 256)

// withIdempotencyKey (v2.25+) is a generic wrapper that
// applies the v2.18 Idempotency-Key protocol to any handler.
// On replay → emits the cached response and short-circuits.
// On conflict → 409. On miss → invokes the inner handler
// against a response recorder, then caches the rendered
// bytes.
//
// Bodies are buffered upfront so the inner handler can read
// them via r.Body normally. Empty body is fine (bulk endpoints).
func withIdempotencyKey(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("Idempotency-Key")
		if key == "" {
			h.ServeHTTP(w, r)
			return
		}
		body, readErr := readAndRestoreBody(r)
		if readErr != nil {
			http.Error(w, "idempotency: read body: "+readErr.Error(), http.StatusBadRequest)
			return
		}
		if handled := tryReplayIdempotency(w, key, body); handled {
			return
		}
		rec := &idempotencyResponseRecorder{
			ResponseWriter: w,
			status:         http.StatusOK,
		}
		h.ServeHTTP(rec, r)
		// Only cache 2xx responses — replaying a 4xx/5xx is
		// surprising and rarely useful.
		if rec.status >= 200 && rec.status < 300 {
			defaultIdempotencyCache.Store(key, body, rec.status, rec.buf.Bytes())
		}
	})
}

// readAndRestoreBody buffers r.Body so the wrapped handler
// can still read it. http.NoBody is preserved for body-less
// requests (avoid allocating an empty bytes.Buffer just to
// satisfy the inner handler's io.ReadCloser).
func readAndRestoreBody(r *http.Request) ([]byte, error) {
	if r.Body == nil || r.Body == http.NoBody {
		return nil, nil
	}
	body, err := io.ReadAll(r.Body)
	_ = r.Body.Close()
	if err != nil {
		return nil, err
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	return body, nil
}

// idempotencyResponseRecorder captures the inner handler's
// status + body so withIdempotencyKey can re-emit it from
// the cache on retry.
type idempotencyResponseRecorder struct {
	http.ResponseWriter
	status      int
	buf         bytes.Buffer
	wroteHeader bool
}

func (r *idempotencyResponseRecorder) WriteHeader(code int) {
	if r.wroteHeader {
		return
	}
	r.wroteHeader = true
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *idempotencyResponseRecorder) Write(p []byte) (int, error) {
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}
	r.buf.Write(p)
	return r.ResponseWriter.Write(p)
}
