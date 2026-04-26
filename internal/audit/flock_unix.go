//go:build !windows

package audit

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// lockExclusive acquires an exclusive advisory lock on the
// audit log file via flock(LOCK_EX). Blocks until the lock
// is granted. Used by FileWriter.Append + appendVerbatim
// (v1.15 chunk 4) so two ElSereno processes appending to
// the same `~/.elsereno/audit.jsonl` serialise — without
// the lock, concurrent writers can produce two entries
// claiming the same prev_hash, corrupting the chain.
//
// The lock is process-scoped (per fd) per POSIX flock(2)
// semantics: closing the fd releases the lock; forking a
// child shares the lock. ElSereno doesn't fork audit-
// writing children, so the simple fd-scoped semantics
// suffice.
//
// Returns the original error from flock unwrapped — the
// caller already wraps with "audit: ..." context.
func (w *FileWriter) lockExclusive() error {
	if w.f == nil {
		return fmt.Errorf("audit: lock on closed writer")
	}
	// #nosec G115 — uintptr-to-int on a kernel-issued fd; never negative or > MaxInt for a process's open files.
	return unix.Flock(int(w.f.Fd()), unix.LOCK_EX)
}

// unlockExclusive releases the flock acquired by
// lockExclusive. Closing the file also releases the lock,
// but explicit unlock keeps the critical section narrow
// (the writer holds the file open for the lifetime of the
// process; without explicit unlock, the lock would persist
// until process exit, blocking every other writer).
func (w *FileWriter) unlockExclusive() error {
	if w.f == nil {
		return nil
	}
	// #nosec G115 — uintptr-to-int on a kernel-issued fd; never negative or > MaxInt for a process's open files.
	return unix.Flock(int(w.f.Fd()), unix.LOCK_UN)
}
