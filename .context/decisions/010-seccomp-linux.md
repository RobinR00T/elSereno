---
id: 010
title: seccomp-bpf sandbox for offensive subprocesses on Linux
status: accepted
date: 2026-04-19
phase: F0
---

# ADR-010: seccomp-bpf sandbox for offensive subprocesses on Linux

## Context
Offensive subprocesses (writes, exploits, harvesting, dial) run code paths
that could, in the face of a bug, be coerced into doing more than intended.
Linux seccomp-bpf is the standard defence-in-depth to cap syscall surface.

## Decision
On Linux, offensive subprocesses spawned under `-tags offensive` run under
a seccomp-bpf filter that restricts syscalls to the minimum required.

Implementation strategy is **dual**:
1. First choice: `github.com/elastic/go-seccomp-bpf`.
2. Fallback A: direct `syscall.Prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER,
   ...)` with a hand-assembled BPF program.
3. Fallback B: `github.com/seccomp/libseccomp-golang` (CGO).

The concrete choice is **deferred to F5**, when seccomp is actually
wired in, and documented in a supplementary ADR at that point. The F0
scaffold does not import any seccomp library.

macOS has no equivalent and is out of scope for the sandbox.

## Consequences
### Positive
- Defence-in-depth against subprocess bugs on Linux.
- Explicit deferral avoids locking in a potentially archived dependency
  (PITF-011).

### Negative / trade-offs
- Extra complexity on Linux; feature parity gap on macOS documented in
  `LEGAL.md` / `SECURITY.md`.

## Alternatives considered
- No sandbox: declined — offensive paths are high-risk.
- Linux-only binary: too drastic; macOS is a first-class dev platform.

## References
- PITF-011; project brief section 7 F5.
