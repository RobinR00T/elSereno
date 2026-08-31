package handlers

import "time"

// ResetIdempotencyCacheForTest swaps the process-global idempotency cache
// for a fresh, empty one and returns a restore func. Black-box tests in
// package handlers_test call it (via t.Cleanup) to isolate a hard-coded
// Idempotency-Key: without it, a key stored on one run leaks into the
// package-global cache and makes the next test — or the next
// `go test -count=N` iteration — see a spurious replay on its first call.
func ResetIdempotencyCacheForTest() func() {
	prev := idempotencyStoreNow()
	SetDefaultIdempotencyCache(newIdempotencyCache(time.Hour, 256))
	return func() { SetDefaultIdempotencyCache(prev) }
}
