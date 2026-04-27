//go:build offensive

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync/atomic"

	"local/elsereno/offensive/confirm"
)

// reloadableHandler wraps a gatedProxyHandler behind an
// atomic.Pointer so SIGUSR1 can swap the underlying allowlist +
// confirm-token without disturbing in-flight connections. v1.17
// chunk 4: the in-process counterpart to v1.15 chunk-5's
// supervisor-restart pattern.
//
// In-flight Handle goroutines see their own snapshot of the
// pointer (loaded at entry) so a swap mid-call doesn't tear
// state. New connections after the swap pick up the new
// allowlist on their first Handle invocation. Authorise on the
// wrapper delegates to the current inner — the initial Authorise
// runs before any Handle, so the wrapper is only ever invoked
// after at least one inner has been installed.
type reloadableHandler struct {
	// inner points at the active gatedProxyHandler. Stored as
	// atomic.Pointer so the SIGUSR1 reload goroutine can swap
	// without taking a lock.
	inner atomic.Pointer[gatedProxyHandler]
}

// newReloadableHandler installs h as the initial inner and
// returns the wrapper.
func newReloadableHandler(h gatedProxyHandler) *reloadableHandler {
	r := &reloadableHandler{}
	r.inner.Store(&h)
	return r
}

// Authorise delegates to the current inner handler. The initial
// Authorise runs before proxy.Server starts; subsequent
// Authorise calls (during reload) are issued by performReload
// directly on the new handler before swap.
func (r *reloadableHandler) Authorise(ctx context.Context) error {
	hp := r.inner.Load()
	if hp == nil {
		return errors.New("reloadable: nil handler")
	}
	return (*hp).Authorise(ctx)
}

// Handle delegates to the snapshot-loaded inner. In-flight
// connections finish with their original allowlist; new
// connections see the post-swap one.
func (r *reloadableHandler) Handle(ctx context.Context, client, upstream io.ReadWriter) error {
	hp := r.inner.Load()
	if hp == nil {
		return errors.New("reloadable: nil handler")
	}
	return (*hp).Handle(ctx, client, upstream)
}

// swap replaces the inner handler. Called from the SIGUSR1
// reload path AFTER the new handler has been authorised
// successfully.
func (r *reloadableHandler) swap(h gatedProxyHandler) {
	r.inner.Store(&h)
}

// performReload re-reads the allow-file + sidecar token,
// builds a new gatedProxyHandler, authorises it, and on success
// swaps it into the wrapper. On any failure, the old handler is
// preserved untouched and a typed error is returned. v1.17
// chunk 4.
//
// Operator workflow (assuming --reload-allow-file enabled +
// --allow-file path used):
//
//  1. Edit /etc/elsereno/<plugin>-gate.yaml (bump
//     `token_generation:` and/or change the allowlist).
//  2. Run `write <plugin> dry-run --token-generation N
//     --allow-file ...` to mint the new confirm-token.
//  3. Write the new token to `<allow-file>.token` (0600).
//  4. `kill -USR1 $pid` → the proxy reloads in-place. New
//     connections use the new allowlist; in-flight finish
//     with the old.
//
// Returns nil on successful swap; non-nil error otherwise.
// Caller logs + audits.
func performReload(ctx context.Context, cmd cmdPrinter, original proxyListenOpts, rt *offensiveRuntime, target *reloadableHandler) error {
	if original.allowFile == "" {
		return errors.New("--reload-allow-file requires --allow-file")
	}
	// Build a fresh opts inheriting immutable session bits + the
	// allow-file path. The allow-file load below populates the
	// plugin-specific allowlist fields. confirmToken comes from
	// the sidecar file; the rest of session-control (target,
	// listen, ppFile, timeouts) is preserved verbatim.
	newOpts := freshReloadOpts(original)
	if err := loadAllowFile(newOpts.allowFile, &newOpts); err != nil {
		return fmt.Errorf("reload: load allow-file: %w", err)
	}
	tokenPath := newOpts.allowFile + ".token"
	tok, err := readSidecarToken(tokenPath)
	if err != nil {
		return fmt.Errorf("reload: read sidecar token %s: %w", tokenPath, err)
	}
	newOpts.confirmToken = tok
	newOpts.confirmTarget = original.confirmTarget // re-use; target byte-match is independent of allow-file
	newOpts.target = original.target
	c := confirm.Confirm{
		AcceptsWrites: newOpts.acceptWrites,
		ConfirmTarget: newOpts.confirmTarget,
		ConfirmToken:  newOpts.confirmToken,
	}
	newHandler, err := buildGatedHandler(newOpts, rt, c)
	if err != nil {
		return fmt.Errorf("reload: build new handler: %w", err)
	}
	if err := authoriseHandler(ctx, newHandler); err != nil {
		return fmt.Errorf("reload: authorise new handler (token / allowlist mismatch?): %w", err)
	}
	target.swap(newHandler)
	cmd.Printf("proxy: SIGUSR1 reload OK — new allowlist active for new connections (in-flight finish with old)\n")
	return nil
}

// freshReloadOpts returns a proxyListenOpts seeded with the
// immutable session bits from `original` but with the plugin-
// specific allowlist fields cleared. Used by performReload so
// the re-loaded allow-file populates fresh slice state instead
// of appending to the original-session lists.
//
// Preserved from original: plugin, target, listen, allowFile,
// acceptWrites, confirmTarget, ppFile, timeouts, maxConns.
//
// Cleared (re-populated by loadAllowFile): every plugin-
// specific allowlist field + confirmToken (read from sidecar
// next).
func freshReloadOpts(original proxyListenOpts) proxyListenOpts {
	return proxyListenOpts{
		plugin:        original.plugin,
		target:        original.target,
		listen:        original.listen,
		allowFile:     original.allowFile,
		acceptWrites:  original.acceptWrites,
		confirmTarget: original.confirmTarget,
		ppFile:        original.ppFile,
		dialTimeout:   original.dialTimeout,
		idleTimeout:   original.idleTimeout,
		maxConns:      original.maxConns,
	}
}

// readSidecarToken loads the new confirm-token from the
// `<allow-file>.token` sidecar. Enforces 0600 permissions to
// match the operator's secret-handling discipline (a confirm-
// token is bearer-equivalent until the session ends).
func readSidecarToken(path string) (string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("token sidecar %s: permissions %#o; require 0600 (chmod 600 %s)", path, fi.Mode().Perm(), path)
	}
	raw, err := os.ReadFile(path) //nolint:gosec // G304 — operator-supplied sidecar path; enforce-0600 above is the contract.
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}

// cmdPrinter is the minimal cobra.Command surface performReload
// needs (just Printf for the success line). Decoupled so the
// reload path can be tested without spinning up a real cobra
// command.
type cmdPrinter interface {
	Printf(format string, args ...any)
}
