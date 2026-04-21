//go:build offensive && linux

package sandbox

import (
	"errors"
	"fmt"
	"runtime"
)

// Load installs the sandbox for the current thread (ADR-042).
//
// It runs in three layers:
//
//  1. `prctl(PR_SET_NO_NEW_PRIVS, 1)` — blocks privilege regain
//     via setuid binaries. Installed unconditionally.
//  2. `PR_SET_SECCOMP` with a per-profile BPF denylist — blocks
//     the escape paths ADR-042 calls out (namespace-escape,
//     module-load, ptrace, bpf, reboot) plus per-profile extras
//     (file-mutate for harvest, network-open for dial). See
//     `bpf_linux.go` for the compiler and `syscalls_linux.go`
//     for the per-arch numbers.
//  3. `runtime.LockOSThread` — the filter is per-thread, so we
//     pin the current goroutine to this OS thread before install
//     so the caller knows the filter survives the call. Callers
//     that want to lift the pin can call `runtime.UnlockOSThread`
//     after Load returns, though the seccomp filter cannot be
//     removed once installed — that is the security guarantee.
//
// The caller is responsible for invoking Load in the CHILD
// subprocess (typically the early init of an exec'd helper
// binary). Calling Load in the parent would seccomp the whole
// ElSereno process, which is fine for a `dial`/`harvest`/
// `exploit` one-shot but fatal for `serve`. Runtime verifications
// at Load time cannot catch this misuse — it's a caller contract.
//
// On architectures with no compiled syscall table (anything
// outside amd64 / arm64 as of v1.1), Load still installs
// NO_NEW_PRIVS and returns Available=true with Kind="seccomp-bpf-partial"
// so the audit entry records what was applied. The BPF filter is
// skipped and Reason reflects why.
func Load(profile Profile) (LoadResult, error) {
	if !profile.Valid() {
		return LoadResult{}, fmt.Errorf("sandbox: unknown profile %q", profile)
	}
	// Pin before the filter install so PR_SET_SECCOMP lands on the
	// thread the caller is running on, and the filter follows that
	// thread for the rest of its life. If we didn't pin, the Go
	// runtime could migrate the goroutine to a different OS thread
	// and subsequent syscalls would not be filtered.
	runtime.LockOSThread()

	prog, progErr := FilterProgram(profile)
	if errors.Is(progErr, ErrArchUnsupported) {
		// Degraded mode: we can still install NO_NEW_PRIVS.
		if err := setNoNewPrivs(); err != nil {
			return LoadResult{}, err
		}
		return LoadResult{
			Profile: profile,
			Availability: Availability{
				Available: true,
				Kind:      "seccomp-bpf-partial",
				Reason:    fmt.Sprintf("NO_NEW_PRIVS installed; BPF filter skipped (%s)", progErr),
			},
		}, nil
	}
	if progErr != nil {
		return LoadResult{}, progErr
	}
	if err := installFilter(prog); err != nil {
		return LoadResult{}, err
	}
	return LoadResult{
		Profile: profile,
		Availability: Availability{
			Available: true,
			Kind:      "seccomp-bpf",
			Reason: fmt.Sprintf("profile=%s arch=%s blocklist-size=%d",
				profile, runtime.GOARCH, (len(prog)-5)),
		},
	}, nil
}

// setNoNewPrivs is the single-step degraded install when the
// BPF filter cannot be compiled for the current arch. Callers
// elsewhere in the package reach through installFilter() which
// also applies NO_NEW_PRIVS; this wrapper exists so the
// degraded path does not pay the empty-program sanity check.
func setNoNewPrivs() error {
	// Import `unix` is via installFilter's file. Keeping the call
	// here avoids an extra dep on this file; prctl is a trivial
	// wrapper we already use elsewhere.
	return prctlNoNewPrivs()
}
