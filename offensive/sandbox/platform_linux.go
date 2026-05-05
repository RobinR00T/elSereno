//go:build offensive && linux

package sandbox

// isLinux is a tiny compile-time probe used by shared tests that
// want to branch between the real kernel path and the stub path
// without repeating build tags everywhere.
func isLinux() bool { return true }

// hasMacOSSandboxInit is unconditionally false on Linux; the
// v1.50 darwin+cgo probe is meaningful only on darwin builds.
func hasMacOSSandboxInit() bool { return false }
