//go:build offensive && linux && !amd64 && !arm64

package sandbox

// seccompSyscallNumber is -1 on unsupported Linux architectures.
// Paths that would consult this never reach the call because
// FilterProgram returns ErrArchUnsupported on the same set, and
// the degraded Load() short-circuits before installFilter runs.
// The constant still has to exist for the file to compile on e.g.
// riscv64 CI runners.
const seccompSyscallNumber = ^uintptr(0) // intentionally wrong; never called
