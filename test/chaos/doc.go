// Package chaos provides fault-injection helpers the protocol test
// suites can chain in front of a real transport:
//
//   - RandomDropReader / RandomDropWriter: drops bytes with
//     configurable probability.
//   - LatencyReader: adds delay before delivering each Read.
//   - FlipBitsWriter: corrupts one bit per N bytes.
//   - EarlyCloser: closes the underlying connection after N bytes.
//
// All helpers are deterministic under a fixed seed so CI reproduces
// failures. Chaos tests live behind the `chaos` build tag so they
// are never pulled into the default run; invoke with
//
//	go test -tags chaos -count=1 ./test/chaos/...
package chaos
