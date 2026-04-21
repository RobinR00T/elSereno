//go:build offensive && !linux

package sandbox

// isLinux is a tiny compile-time probe used by shared tests that
// want to branch between the real kernel path and the stub path
// without repeating build tags everywhere.
func isLinux() bool { return false }
