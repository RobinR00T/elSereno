//go:build offensive && darwin && cgo

package sandbox

// isLinux mirrors the !linux file (the cgo-darwin path is
// still not Linux). Returning false keeps the test
// branching unchanged for the seccomp coverage tests.
func isLinux() bool { return false }

// hasMacOSSandboxInit reports that v1.50's cgo wrapper for
// sandbox_init(3) is in this binary. Used by
// sandbox_test.go to skip the "expects Available=false"
// stub-coverage test under the cgo build.
func hasMacOSSandboxInit() bool { return true }
