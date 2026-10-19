// Package scanner resolves hostnames (A + AAAA + IDN), dedupes
// (address, port) tuples, and issues probes with rate limits, jitter
// and retries. CircuitBreaker (breaker.go) exists but no command wires
// it in yet, so a scan has no per-host breaker today.
package scanner
