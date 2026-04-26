//go:build windows

package audit

// Stub: ElSereno is Linux + macOS only per CLAUDE.md (Windows
// support is tracked in the v1.15+ backlog as a cross-cutting
// item including AppContainer / Job Objects rather than
// seccomp + flock). When Windows lands, replace these stubs
// with LockFileEx-based implementations.

func (w *FileWriter) lockExclusive() error   { return nil }
func (w *FileWriter) unlockExclusive() error { return nil }
