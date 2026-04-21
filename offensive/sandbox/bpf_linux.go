//go:build offensive && linux

package sandbox

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// BPF seccomp plumbing. Implements a per-profile denylist filter
// per ADR-042: PR_SET_NO_NEW_PRIVS + SECCOMP_SET_MODE_FILTER over a
// program that returns SECCOMP_RET_ERRNO|EPERM for every syscall
// that matches the profile's blocklist and SECCOMP_RET_ALLOW for
// everything else.
//
// A DENYLIST is deliberate: the Go runtime uses ~50 syscalls just
// to GC + schedule goroutines, and an allowlist that's tight
// enough to be meaningful is fragile across Go versions + distros.
// The blocklist covers the escape paths ADR-042 calls out
// (privilege-regain, namespace-escape, module-load, ptrace, bpf,
// reboot) plus the per-profile extras (file-mutate for harvest,
// network-open for dial).
//
// Architectures: x86_64 + aarch64 supported. Other arches drop
// back to the pre-v1.1 behaviour of only installing
// PR_SET_NO_NEW_PRIVS with a non-fatal warning in
// Availability.Reason so the process still runs (CI on ppc64/
// riscv64 is a fringe case for the offensive workflow but must
// not crash).

// BPF instruction opcodes we use. Re-declared locally so we don't
// pull in `golang.org/x/net/bpf` just for the constants.
const (
	bpfLD  uint16 = 0x00 // load
	bpfW   uint16 = 0x00 // word (32-bit)
	bpfABS uint16 = 0x20 // absolute offset

	bpfJMP uint16 = 0x05 // conditional jump
	bpfJEQ uint16 = 0x10 // jump if ==
	bpfK   uint16 = 0x00 // immediate operand

	bpfRET uint16 = 0x06 // return

	// Seccomp return values (full 32-bit action+data).
	seccompRetAllow uint32 = 0x7fff0000
	seccompRetKill  uint32 = 0x00000000 // SECCOMP_RET_KILL_PROCESS on recent kernels
	seccompRetErrno uint32 = 0x00050000 // | errno
)

// Offsets into struct seccomp_data (see <linux/seccomp.h>).
const (
	seccompDataOffsetNR   = 0
	seccompDataOffsetArch = 4
)

// AUDIT_ARCH_* values we care about (see <linux/audit.h>).
const (
	auditArchX86_64  uint32 = 0xC000003E
	auditArchAarch64 uint32 = 0xC00000B7
)

// seccomp(2) mode constants (see <linux/seccomp.h>).
const (
	seccompSetModeFilter = 1

	// SECCOMP_FILTER_FLAG_TSYNC synchronises the filter across
	// every thread in the caller's thread-group. Without it the
	// filter only covers the calling thread — which defeats the
	// purpose inside a Go program, where the runtime freely
	// schedules goroutines across OS threads. With TSYNC the
	// kernel refuses to install the filter if ANY peer thread
	// cannot accept it (e.g. one already runs a different
	// filter), returning the offending tid in errno. For fresh
	// offensive CLI processes that's never the case.
	seccompFilterFlagTsync uint32 = 1
)

// ErrArchUnsupported is returned by FilterProgram when we don't
// carry a syscall-number table for the running GOARCH. The caller
// should degrade to "seccomp unavailable" rather than fail the
// whole operation (see Load on non-supported arch).
var ErrArchUnsupported = errors.New("sandbox: seccomp filter not compiled for this architecture")

// FilterProgram returns the compiled seccomp BPF program for p,
// along with the AUDIT_ARCH value that must match at runtime.
// Returns ErrArchUnsupported when the running GOARCH isn't
// amd64/arm64; on that arch the filter is a compile-time
// constant so tests don't need a kernel.
func FilterProgram(p Profile) ([]unix.SockFilter, error) {
	if !p.Valid() {
		return nil, fmt.Errorf("sandbox: unknown profile %q", p)
	}
	arch, nums, err := archFor(runtime.GOARCH)
	if err != nil {
		return nil, err
	}
	blocked := blockedSyscalls(p, nums)
	return compileFilter(arch, blocked), nil
}

// compileFilter emits a denylist seccomp filter for the given arch +
// blocked syscall numbers:
//
//	00: LD  [arch]
//	01: JEQ auditArch, +1, kill
//	02: RET KILL   (wrong arch)
//	03: LD  [nr]
//	04+ for each blocked nr: JEQ blocked, return-errno, +1
//	N-1: RET ALLOW
//	N:   RET ERRNO|EPERM   (return-errno label)
//
// Jumps are relative byte offsets (8-bit Jt/Jf); keeping the
// return-errno label at the tail lets every denylist entry target
// it via a single jt=0 jf= computed at emit time.
func compileFilter(auditArch uint32, blocked []uint32) []unix.SockFilter {
	// 5 fixed slots + 1 per blocked syscall + 2 tail returns.
	// We build bottom-up for the jump offsets, then assemble.
	var insns []unix.SockFilter

	// [0] load arch
	insns = append(insns, unix.SockFilter{Code: bpfLD | bpfW | bpfABS, K: seccompDataOffsetArch})
	// [1] jeq auditArch, 1, 0  (if match → fall through; if mismatch → skip one)
	insns = append(insns, unix.SockFilter{Code: bpfJMP | bpfJEQ | bpfK, Jt: 1, Jf: 0, K: auditArch})
	// [2] ret KILL (wrong arch)
	insns = append(insns, unix.SockFilter{Code: bpfRET | bpfK, K: seccompRetKill})
	// [3] load syscall nr
	insns = append(insns, unix.SockFilter{Code: bpfLD | bpfW | bpfABS, K: seccompDataOffsetNR})

	// Each blocked syscall is one JEQ. On match it jumps to the
	// RET ERRNO|EPERM instruction at the very end; on miss it
	// falls through to the next JEQ.
	//
	// We know the layout: after all JEQs there's one RET ALLOW
	// and then one RET ERRNO. The jump target for each JEQ is the
	// RET ERRNO, so its Jt offset equals
	//   (len(blocked) - i - 1)  +  1   (skip the RET ALLOW too).
	for i, nr := range blocked {
		jt := uint8(len(blocked) - i - 1 + 1)
		insns = append(insns, unix.SockFilter{
			Code: bpfJMP | bpfJEQ | bpfK,
			Jt:   jt,
			Jf:   0,
			K:    nr,
		})
	}
	// tail RET ALLOW
	insns = append(insns, unix.SockFilter{Code: bpfRET | bpfK, K: seccompRetAllow})
	// tail RET ERRNO | EPERM
	insns = append(insns, unix.SockFilter{
		Code: bpfRET | bpfK,
		K:    seccompRetErrno | uint32(unix.EPERM),
	})
	return insns
}

// archFor returns the AUDIT_ARCH value + syscall-number table for
// the current GOARCH. Only x86_64 and aarch64 ship in v1.1.
func archFor(goarch string) (uint32, syscallNums, error) {
	switch goarch {
	case "amd64":
		return auditArchX86_64, syscallsAMD64, nil
	case "arm64":
		return auditArchAarch64, syscallsARM64, nil
	default:
		return 0, syscallNums{}, ErrArchUnsupported
	}
}

// installFilter registers prog with the kernel via
// prctl(PR_SET_NO_NEW_PRIVS, 1) + seccomp(SECCOMP_SET_MODE_FILTER, 0, &prog).
// Runs the CURRENT thread into seccomp; callers must have pinned
// the goroutine via runtime.LockOSThread() in the caller path that
// wants the filter to stay on that OS thread.
//
// We use seccomp(2) directly rather than prctl(PR_SET_SECCOMP, …)
// because the prctl path doesn't accept the standard SECCOMP_SET_MODE_*
// flag family on older kernels and some hardened Linux distributions
// restrict prctl PR_SET_SECCOMP via their own seccomp profile
// (ironic, but seccomp(2) is allowed).
func installFilter(prog []unix.SockFilter) error {
	if len(prog) == 0 {
		return errors.New("sandbox: empty filter program")
	}
	if err := prctlNoNewPrivs(); err != nil {
		return err
	}
	fprog := unix.SockFprog{
		Len:    uint16(len(prog)), //nolint:gosec // G115 — prog length bounded by syscall-table size ≤ 1000 entries
		Filter: &prog[0],
	}
	// seccomp(SECCOMP_SET_MODE_FILTER, TSYNC, &fprog). TSYNC
	// extends the filter to every thread in the thread-group so
	// Go's goroutine scheduler doesn't hop a sensitive goroutine
	// onto an unfiltered OS thread. The syscall NR varies per
	// arch — defined in seccomp_<arch>.go.
	_, _, errno := unix.Syscall(
		seccompSyscallNumber,
		uintptr(seccompSetModeFilter),
		uintptr(seccompFilterFlagTsync),
		uintptr(unsafe.Pointer(&fprog)),
	)
	if errno != 0 {
		return fmt.Errorf("sandbox: seccomp(SET_MODE_FILTER): %w", errno)
	}
	return nil
}

// prctlNoNewPrivs is the minimum-privilege half of the seccomp
// pair. Exposed separately so the degraded-arch path can still
// install it when the BPF filter is skipped.
func prctlNoNewPrivs() error {
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("sandbox: PR_SET_NO_NEW_PRIVS: %w", err)
	}
	return nil
}
