//go:build offensive && linux && amd64

package sandbox

// seccompSyscallNumber is the NR for the seccomp(2) syscall on
// x86_64 Linux. Not in unix package's portable exports, so we
// declare it inline. Source: arch/x86/entry/syscalls/syscall_64.tbl.
const seccompSyscallNumber = 317
