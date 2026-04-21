//go:build offensive && linux && arm64

package sandbox

// seccompSyscallNumber is the NR for the seccomp(2) syscall on
// aarch64 Linux. Sourced from include/uapi/asm-generic/unistd.h.
const seccompSyscallNumber = 277
