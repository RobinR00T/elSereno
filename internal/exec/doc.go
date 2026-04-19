// Package exec provides SafeCommand — the only sanctioned way to spawn
// subprocesses from ElSereno.
//
// The contract is deliberate (ADR-024, PITF-023):
//
//   - Callers construct a CommandSpec{Name, Flags, Positional}.
//   - argv is assembled as [Name] ++ Flags ++ ["--"] ++ Positional; the
//     "--" separator is always present.
//   - Name is validated via exec.LookPath and its resolved path must be
//     under one of the configured allow-paths.
//   - Each Flags[i] must start with "-" and contain no shell metacharacters.
//   - Each Positional[i] is validated by the caller-supplied validator.
//   - shell=true is never used.
//
// A single `//nolint:gosec G204` sits on the os/exec call below with a
// short rationale; callers do not add their own.
package exec
