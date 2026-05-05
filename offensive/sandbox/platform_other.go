//go:build offensive && !linux && (!darwin || !cgo)

package sandbox

// isLinux is a tiny compile-time probe used by shared tests that
// want to branch between the real kernel path and the stub path
// without repeating build tags everywhere.
func isLinux() bool { return false }

// hasMacOSSandboxInit is the v1.50 probe for the darwin+cgo
// path. False here = stub Load path is in effect (this file
// compiles on every non-Linux platform that doesn't have
// the cgo-darwin file lit up).
func hasMacOSSandboxInit() bool { return false }
