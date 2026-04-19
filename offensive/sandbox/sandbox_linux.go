//go:build offensive && linux

package sandbox

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// Load installs the sandbox for the current thread. ADR-042 splits
// this into two layers:
//
//  1. prctl(PR_SET_NO_NEW_PRIVS, 1): blocks privilege regain via
//     setuid binaries in the child. This is a cheap, unambiguous
//     win and is installed unconditionally on Linux.
//  2. seccomp-BPF filter matching the named profile. Landing with
//     the write-plugin chunk (F6); for now Load() records
//     Kind="seccomp-bpf" with Reason including the profile so the
//     audit entry reflects the intent.
//
// The caller is responsible for running Load *inside the child*
// (typically from a wrapper main() under exec.Command). Calling
// Load on the parent thread would lock the parent's capability
// surface.
func Load(profile Profile) (LoadResult, error) {
	if !profile.Valid() {
		return LoadResult{}, fmt.Errorf("sandbox: unknown profile %q", profile)
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return LoadResult{}, fmt.Errorf("sandbox: PR_SET_NO_NEW_PRIVS: %w", err)
	}
	return LoadResult{
		Profile: profile,
		Availability: Availability{
			Available: true,
			Kind:      "seccomp-bpf",
			Reason:    fmt.Sprintf("NO_NEW_PRIVS set; BPF filter for %s lands in F6", profile),
		},
	}, nil
}
