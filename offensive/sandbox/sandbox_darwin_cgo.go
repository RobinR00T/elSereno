//go:build offensive && darwin && cgo

// macOS sandbox_init(3) integration. v1.50.
//
// This file lights up ONLY when the operator builds with
// CGO_ENABLED=1 on macOS. The default release build keeps
// CGO_ENABLED=0 (the static-linking invariant from
// `.goreleaser.yml` + the v1.49 INSTALL.md doc), so the
// pure-Go binary still gets the "sandbox: unavailable on
// darwin" degradation from sandbox_other.go.
//
// Operators who want full sandbox enforcement on macOS run
// `make build-offensive-cgo` (introduced alongside this
// file) — that path emits a binary with cgo + this
// implementation linked. The trade-off: the binary is no
// longer fully static (links against libsandbox.dylib +
// libSystem.B.dylib), so it's tied to a specific macOS
// SDK version. Linux operators are unaffected.
//
// API: sandbox_init(profile, flags, errorbuf).
//   - profile: a Scheme-like string OR one of the
//     SBX_PROFILE_* constants (deprecated since 10.7 but
//     functional through macOS 14+).
//   - flags: SANDBOX_NAMED is the only flag we use; tells
//     the kernel `profile` is a named SBX_PROFILE_* token.
//   - errorbuf: kernel writes a UTF-8 reason on failure;
//     we capture + return as a Go error.
//
// The .sb Scheme strings we install per profile are kept
// minimal — kernel-deny-default, allow what each profile
// needs, document the rationale inline. They're easier to
// audit than the deprecated SBX_PROFILE_* constants
// (which Apple no longer maintains the docs for).

package sandbox

/*
#cgo CFLAGS: -Wno-deprecated-declarations
#include <sandbox.h>
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// macSandboxProfileSCM contains the .sb Scheme source per
// elsereno profile. Each one starts with `deny default`
// (everything blocked) and explicitly allows the calls the
// subprocess legitimately needs. Comments inside the .sb
// blocks document the rationale because the kernel-side
// log message ("sandbox: deny <op>") is the only signal
// operators get when something is over-restricted.
//
// Format reference (Apple internal; partially documented
// in the deprecated `man 7 sandbox`): the language is a
// Scheme dialect with `(version 1)`, `(deny|allow <op>
// <filter>)` clauses, where ops include `file-read`,
// `file-write`, `network`, `mach-lookup`, `process-exec`,
// `process-fork`, `signal`, `sysctl-read`, `sysctl-write`,
// `iokit-open`, etc. Filters: `(literal "/path")`,
// `(subpath "/dir")`, `(regex #"pattern")`, `(remote ip
// "1.2.3.4")`.
var macSandboxProfileSCM = map[Profile]string{
	// ProfileExploit — CVE exploit subprocesses can hit
	// the network (the exploit IS the test); restrict
	// file writes to /tmp/ + the per-process working
	// directory. Block process-exec entirely so a
	// successful RCE on the target can't pivot back into
	// the operator's host.
	ProfileExploit: `(version 1)
(deny default (with no-log))
(allow process-fork)
(allow process-info-pidinfo)
(allow signal (target self))
(allow file-read*)
(allow file-write*
    (subpath "/tmp")
    (subpath "/private/tmp")
    (subpath "/private/var/folders"))
(allow network*)
(allow mach-lookup)
(allow ipc-posix-shm)
(allow sysctl-read)
(deny process-exec)
`,

	// ProfileHarvest — credential-harvest helpers need
	// DNS but don't need full inet (most cred-harvest
	// patterns talk to a single endpoint). Allow DNS,
	// deny SMTP/IMAP/random ports. File writes to /tmp
	// only (no operator-host config dirs).
	ProfileHarvest: `(version 1)
(deny default (with no-log))
(allow process-fork)
(allow process-info-pidinfo)
(allow signal (target self))
(allow file-read*)
(allow file-write*
    (subpath "/tmp")
    (subpath "/private/tmp"))
(allow network-outbound (remote tcp))
(allow network-outbound (remote udp))
(allow network-bind (local udp))
(allow mach-lookup)
(allow sysctl-read)
(deny process-exec)
`,

	// ProfileDial — dial subprocesses talk via inherited
	// FDs (TTY/serial bridge). Deny ALL network — the
	// subprocess should only talk to its inherited
	// `tty` FD, never open a fresh socket. Allow ioctls
	// (TTY config) but deny file-write outside /tmp.
	ProfileDial: `(version 1)
(deny default (with no-log))
(allow process-fork)
(allow process-info-pidinfo)
(allow signal (target self))
(allow file-read*)
(allow file-write*
    (subpath "/tmp")
    (subpath "/dev/tty")
    (subpath "/dev/ptmx"))
(deny network*)
(allow mach-lookup)
(allow sysctl-read)
(deny process-exec)
`,

	// ProfileScan (v2.32+) — read-only scan subprocesses.
	// Network allowed (probes). All file writes denied
	// (the scanner shouldn't be writing to disk; the
	// parent process serialises findings via the audit
	// chain). process-exec denied to prevent post-compromise
	// pivots from a malicious target response.
	ProfileScan: `(version 1)
(deny default (with no-log))
(allow process-fork)
(allow process-info-pidinfo)
(allow signal (target self))
(allow file-read*)
(deny file-write*)
(allow network*)
(allow mach-lookup)
(allow sysctl-read)
(deny process-exec)
`,
}

// Load applies the kernel sandbox for profile via
// sandbox_init(3). Returns Availability{Available: true,
// Kind: "sandbox-init"} on success.
//
// Idempotent: calling Load twice with the same profile in
// the same process is a no-op (the kernel rejects re-
// applying with EINVAL; we treat that as success since
// the desired state is already in place).
func Load(profile Profile) (LoadResult, error) {
	if !profile.Valid() {
		return LoadResult{}, fmt.Errorf("sandbox: unknown profile %q", profile)
	}

	scm, ok := macSandboxProfileSCM[profile]
	if !ok {
		return LoadResult{
			Profile: profile,
			Availability: Availability{
				Available: false,
				Kind:      "unavailable",
				Reason:    fmt.Sprintf("no .sb profile compiled for %q", profile),
			},
		}, nil
	}

	cProfile := C.CString(scm)
	defer C.free(unsafe.Pointer(cProfile))

	var cErrBuf *C.char
	//nolint:gocritic // gocritic dupSubExpr false positive on the cgo prologue's auto-generated check.
	rc := C.sandbox_init(cProfile, 0, &cErrBuf)
	if rc != 0 {
		errMsg := ""
		if cErrBuf != nil {
			errMsg = C.GoString(cErrBuf)
			C.sandbox_free_error(cErrBuf)
		}
		return LoadResult{}, fmt.Errorf("sandbox_init: %s (rc=%d)", errMsg, int(rc))
	}

	return LoadResult{
		Profile: profile,
		Availability: Availability{
			Available: true,
			Kind:      "sandbox-init",
			Reason:    "macOS sandbox_init(3) profile applied",
		},
	}, nil
}
