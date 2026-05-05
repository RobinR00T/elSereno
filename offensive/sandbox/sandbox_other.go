//go:build offensive && !linux && (!darwin || !cgo)

package sandbox

import "fmt"

// Load on non-Linux is a declared degradation: the runtime returns
// Available=false with a clear reason. Offensive subprocess execution
// continues (matching the F0 macOS developer workflow), but the
// audit entry records sandbox=unavailable so operators know to
// treat the result as best effort. See ADR-042.
//
// FilterProgram / blockedSyscalls / compileFilter are NOT exported
// on non-Linux — seccomp-BPF is a Linux kernel feature with no
// direct analogue elsewhere. Tests that validate the filter
// program build under `//go:build linux` for that reason.
func Load(profile Profile) (LoadResult, error) {
	if !profile.Valid() {
		return LoadResult{}, fmt.Errorf("sandbox: unknown profile %q", profile)
	}
	return LoadResult{
		Profile: profile,
		Availability: Availability{
			Available: false,
			Kind:      "unavailable",
			Reason:    "seccomp-bpf is a Linux-only feature; ADR-042 allows degraded continuation on other platforms",
		},
	}, nil
}
