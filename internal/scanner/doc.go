// Package scanner resolves hostnames (A + AAAA + IDN), dedupes
// (address, port) tuples, and issues probes with rate limits, jitter
// and retries. HostPacer (pacer.go) caps probes in flight per address
// and spaces their starts; it can be shared across runs so the pace
// holds from one plugin to the next. Profile (profile.go) names the
// pace presets behind --profile (aggressive, normal, safe, fragile). CircuitBreaker (breaker.go) exists but no command wires
// it in yet, so a scan has no per-host breaker today.
package scanner
