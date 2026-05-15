package handlers

import (
	"crypto/sha256"
	"encoding/hex"
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
