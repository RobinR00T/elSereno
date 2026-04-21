//go:build offensive

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"

	"github.com/spf13/cobra"

	"local/elsereno/internal/audit"
	"local/elsereno/internal/core"
	"local/elsereno/internal/creds"
	"local/elsereno/offensive/confirm"
	"local/elsereno/offensive/sandbox"
)

// offensiveRuntime bundles the objects every offensive CLI verb
// needs: the unlocked vault (so tokens can be derived), the audit
// writer (so every Authorize call emits a chained row), the
// confirm.Auditor adapter, and the actor label (used as the
// `Actor` column on audit entries).
type offensiveRuntime struct {
	Vault   *creds.Vault
	Writer  audit.Writer
	Auditor confirm.Auditor
	Actor   string
	path    string // audit.jsonl path (for the CLI to print after use)
}

// newOffensiveRuntime wires the runtime up. `passphraseFile` is the
// optional --vault-passphrase-file path; empty falls back to the
// TTY prompt. Callers MUST defer runtime.Close().
func newOffensiveRuntime(cmd *cobra.Command, passphraseFile string) (*offensiveRuntime, error) {
	v, err := unlockVault(cmd, passphraseFile)
	if err != nil {
		return nil, err
	}
	auditPath, err := defaultAuditPath()
	if err != nil {
		_ = v.Lock
		return nil, fail(core.ExitOSErr, err)
	}
	w, err := audit.OpenFileWriter(auditPath)
	if err != nil {
		return nil, fail(core.ExitIOErr, err)
	}
	actor := currentActor()
	return &offensiveRuntime{
		Vault:   v,
		Writer:  w,
		Auditor: confirm.NewAuditor(w, actor),
		Actor:   actor,
		path:    auditPath,
	}, nil
}

// Close releases the audit writer's file handle. Safe to call
// multiple times.
func (r *offensiveRuntime) Close() {
	if fw, ok := r.Writer.(*audit.FileWriter); ok && fw != nil {
		_ = fw.Close()
	}
}

// AuditPath returns the on-disk path of the audit log for
// operator-facing messages.
func (r *offensiveRuntime) AuditPath() string { return r.path }

// newAuditOnlyRuntime opens the audit writer without unlocking
// the vault. Harvest probes don't need vault-derived tokens —
// they read default credential lists and emit observations — but
// they DO need to record the sandbox load event in the audit
// chain, same as the write/exploit verbs. The returned runtime's
// Vault field is nil; callers that pass it to a verb requiring a
// vault will see a clear error, not a silent bypass.
func newAuditOnlyRuntime() (*offensiveRuntime, error) {
	auditPath, err := defaultAuditPath()
	if err != nil {
		return nil, fail(core.ExitOSErr, err)
	}
	w, err := audit.OpenFileWriter(auditPath)
	if err != nil {
		return nil, fail(core.ExitIOErr, err)
	}
	actor := currentActor()
	return &offensiveRuntime{
		Vault:   nil,
		Writer:  w,
		Auditor: confirm.NewAuditor(w, actor),
		Actor:   actor,
		path:    auditPath,
	}, nil
}

// ApplySandbox installs the seccomp-bpf profile matching the
// category of the in-flight offensive operation. On Linux this
// kernel-filters the rest of the process (TSYNC across every
// goroutine-backing thread) so a payload that triggers shell
// escape, ptrace, or module load in the exploit handler still
// can't pivot out of ElSereno's process. On other platforms it
// is a no-op that records sandbox=unavailable in the audit chain.
//
// An audit entry of type `sandbox_load` lands alongside the
// Authorize entry so operators see both the authorisation and
// the sandbox state for the same operation.
func (r *offensiveRuntime) ApplySandbox(ctx context.Context, profile sandbox.Profile) error {
	res, err := sandbox.Load(profile)
	if err != nil {
		// Record the failure in the audit chain so the operator
		// sees that the sandbox refused to install BEFORE the
		// network I/O runs.
		_, _ = r.Writer.Append(ctx, audit.Entry{
			EventType: audit.EventOffSandbox,
			Actor:     r.Actor,
			Payload:   sandboxAuditPayload(profile, sandbox.LoadResult{}, err),
		})
		return err
	}
	_, _ = r.Writer.Append(ctx, audit.Entry{
		EventType: audit.EventOffSandbox,
		Actor:     r.Actor,
		Payload:   sandboxAuditPayload(profile, res, nil),
	})
	return nil
}

// sandboxAuditPayload renders the JSONB body embedded in the
// audit Entry.Payload so operators see profile + availability
// + any error in one line of `jq` output.
func sandboxAuditPayload(profile sandbox.Profile, res sandbox.LoadResult, loadErr error) []byte {
	body := map[string]any{
		"profile":   string(profile),
		"available": res.Availability.Available,
		"kind":      res.Availability.Kind,
		"reason":    res.Availability.Reason,
	}
	if loadErr != nil {
		body["error"] = loadErr.Error()
		body["available"] = false
	}
	b, err := json.Marshal(body)
	if err != nil {
		return []byte(`{"profile":"unknown","error":"marshal failed"}`)
	}
	return b
}

// currentActor returns the operator name. Falls back to
// `$USER`, then to "operator".
func currentActor() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	if env := os.Getenv("USER"); env != "" {
		return env
	}
	return "operator"
}

// defaultAuditPath returns ~/.elsereno/audit.jsonl, creating the
// parent dir if missing (mode 0700).
func defaultAuditPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("audit: home dir: %w", err)
	}
	dir := filepath.Join(home, ".elsereno")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("audit: mkdir %s: %w", dir, err)
	}
	return filepath.Join(dir, "audit.jsonl"), nil
}
