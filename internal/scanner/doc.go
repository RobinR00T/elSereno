// Package scanner resolves hostnames (A + AAAA + IDN), dedupes
// (address, port) tuples, and issues probes with rate limits, jitter,
// retries, and a circuit breaker. F0 exposes only the public surface.
package scanner
