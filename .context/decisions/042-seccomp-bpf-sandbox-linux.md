---
id: 042
title: Linux seccomp-bpf sandbox for offensive subprocesses
status: accepted
date: 2026-04-19
phase: F5
supersedes-partial: 010
---

# ADR-042: Linux seccomp-bpf sandbox for offensive subprocesses

## Context
ADR-010 deferred the sandbox library decision to F5. F5 now wants a
concrete answer: when an offensive subprocess is spawned (exploit
binary, CVE PoC, credential harvester that shells out to nmap NSE),
it must run under a syscall-filter that prevents the obvious escape
paths — file I/O outside the working directory, network except the
target, `ptrace`, unshare, `mount`, kernel-module load, etc.

## Decision
We adopt `github.com/elastic/go-seccomp-bpf` as the sandbox library on
Linux. Selection rationale:

- **Pure-Go, kernel-backed**: loads a BPF filter via the native
  `prctl(PR_SET_NO_NEW_PRIVS)` + `seccomp(SECCOMP_SET_MODE_FILTER)`
  flow; no cgo, no hidden C dependency.
- **Maintained**: Elastic uses it in Beats shipped on millions of
  production hosts; recent commits in the last quarter.
- **Profile format**: YAML/Go DSL syntax that composes cleanly with a
  small set of named profiles (`offensive/sandbox/profiles/`).
- **Observability**: supports `SECCOMP_RET_LOG` for dry-run mode so we
  can validate a profile against a real run without killing the
  process.

On non-Linux, the sandbox package compiles to a no-op with a logged
warning — offensive subprocess is still allowed (matches F0 posture
for macOS dev workflows) but the audit event records
`sandbox=unavailable`.

### Profiles
- `exploit` — lift `read`, `write`, `close`, `mmap`, `munmap`,
  `fcntl`, `poll`, `epoll_*`, `socket` (AF_INET/AF_INET6 only via
  filter arg-equality), `connect`, `recvfrom`, `sendto`, `exit`,
  `exit_group`, `rt_sigaction`, `rt_sigreturn`, `nanosleep`,
  `clock_gettime`, `gettimeofday`, `getpid`, `getuid`, `geteuid`.
  Block: `execve`, `execveat`, `fork`, `clone` (except thread-clone
  with CLONE_THREAD), `unshare`, `mount`, `ptrace`, `kexec_load`,
  `init_module`, `finit_module`, `delete_module`,
  `bpf`, `reboot`, `setns`, `pivot_root`.
- `harvest` — same base + `getaddrinfo`-backing (`sendmmsg`,
  `recvmmsg`) for DNS. Block file writes (`openat` with `O_WRONLY |
  O_RDWR | O_CREAT` is argument-filtered to `-EPERM`).
- `dial` — TTY + modem path; allow `ioctl` on `/dev/tty*`;
  `termios` goes through `ioctl` so it's whitelisted. Block all
  network socket calls.

### Enforcement
Before `exec.Command` runs an offensive subprocess, the parent
registers the profile in a `ProcAttr.Setsid = true` + `Pdeathsig =
SIGKILL` block, then `go-seccomp-bpf.Load(profile)` runs **in the
child** via `cmd.Process.Signal` precursor. On load failure, the
subprocess terminates with code 129 and the audit payload records
the error.

### Testing
Linux CI includes a `make sandbox-integration` job (build tag
`sandbox_integration`) that runs a tiny "attacker" helper which
attempts each blocked syscall under each profile and expects
EPERM/EACCES. The test failure modes are fatal (not warnings).

## Consequences

### Positive
- Concrete library decision closes ADR-010 loose end.
- Pure-Go keeps the supply-chain surface small (ADR-002).
- Profiles are named and version-controlled; changes to a profile
  require an ADR note citing which attack surface motivated it.

### Negative / trade-offs
- macOS has no equivalent in pure Go without cgo into
  `sandbox_init(3)`; we accept the "log and continue" degradation
  during operator development. Operators running offensive in
  production MUST use Linux — documented in `SECURITY.md`.
- A BPF filter that passes a carefully-crafted exploit is still an
  unknown; the sandbox is defence-in-depth, not the primary control.

## Alternatives considered
- **`seccomp` from `libseccomp` via cgo**: rejected — cgo dependency
  fights ADR-002.
- **`gVisor`**: excellent isolation but requires a sidecar runtime
  we are not willing to ship.
- **No sandbox, rely on triple-confirm**: rejected — defence in
  depth is the point; we want both.

## References
- ADR-002 (supply-chain posture).
- ADR-010 (original deferral).
- ADR-039 (triple-confirm; the sandbox is orthogonal to authorise).
- `github.com/elastic/go-seccomp-bpf` @ v1.x.
- Linux `prctl(2)`, `seccomp(2)`.
