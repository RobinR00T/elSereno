//go:build offensive

package main

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"

	"github.com/spf13/cobra"

	"local/elsereno/internal/audit"
	"local/elsereno/internal/core"
	"local/elsereno/internal/creds"
	"local/elsereno/offensive/confirm"
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
