//go:build offensive

package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// stubGatedHandler is a minimal gatedProxyHandler used by the
// reloadableHandler unit tests. Tracks how many times Authorise
// + Handle were called and which "version" of the handler is
// active.
type stubGatedHandler struct {
	id              string
	authoriseCalled atomic.Int32
	handleCalled    atomic.Int32
	authoriseErr    error
}

func (s *stubGatedHandler) Authorise(_ context.Context) error {
	s.authoriseCalled.Add(1)
	return s.authoriseErr
}

func (s *stubGatedHandler) Handle(_ context.Context, _, _ io.ReadWriter) error {
	s.handleCalled.Add(1)
	return nil
}

// TestReloadableHandler_DelegatesAuthorise — Authorise on the
// wrapper delegates to the current inner.
func TestReloadableHandler_DelegatesAuthorise(t *testing.T) {
	inner := &stubGatedHandler{id: "v1"}
	r := newReloadableHandler(inner)
	if err := r.Authorise(context.Background()); err != nil {
		t.Fatalf("Authorise() unexpected error: %v", err)
	}
	if got := inner.authoriseCalled.Load(); got != 1 {
		t.Errorf("inner.authoriseCalled = %d, want 1", got)
	}
}

// TestReloadableHandler_DelegatesHandle — Handle on the wrapper
// delegates to the current inner.
func TestReloadableHandler_DelegatesHandle(t *testing.T) {
	inner := &stubGatedHandler{id: "v1"}
	r := newReloadableHandler(inner)
	if err := r.Handle(context.Background(), nil, nil); err != nil {
		t.Fatalf("Handle() unexpected error: %v", err)
	}
	if got := inner.handleCalled.Load(); got != 1 {
		t.Errorf("inner.handleCalled = %d, want 1", got)
	}
}

// TestReloadableHandler_SwapReplacesInner — swap installs the
// new inner; subsequent calls go to v2, not v1.
func TestReloadableHandler_SwapReplacesInner(t *testing.T) {
	v1 := &stubGatedHandler{id: "v1"}
	v2 := &stubGatedHandler{id: "v2"}
	r := newReloadableHandler(v1)

	// Before swap: v1 receives the call.
	_ = r.Handle(context.Background(), nil, nil)
	if got := v1.handleCalled.Load(); got != 1 {
		t.Errorf("v1.handleCalled before swap = %d, want 1", got)
	}

	r.swap(v2)
	_ = r.Handle(context.Background(), nil, nil)

	if got := v1.handleCalled.Load(); got != 1 {
		t.Errorf("v1.handleCalled after swap = %d, want 1 (no new calls to v1)", got)
	}
	if got := v2.handleCalled.Load(); got != 1 {
		t.Errorf("v2.handleCalled = %d, want 1", got)
	}
}

// TestReloadableHandler_AuthoriseAfterSwap — Authorise after
// swap delegates to the new inner.
func TestReloadableHandler_AuthoriseAfterSwap(t *testing.T) {
	v1 := &stubGatedHandler{id: "v1"}
	v2 := &stubGatedHandler{id: "v2"}
	r := newReloadableHandler(v1)
	r.swap(v2)
	if err := r.Authorise(context.Background()); err != nil {
		t.Fatalf("Authorise() unexpected error: %v", err)
	}
	if got := v1.authoriseCalled.Load(); got != 0 {
		t.Errorf("v1.authoriseCalled after swap = %d, want 0 (swap should detach v1)", got)
	}
	if got := v2.authoriseCalled.Load(); got != 1 {
		t.Errorf("v2.authoriseCalled = %d, want 1", got)
	}
}

// TestReadSidecarToken_HappyPath — 0600 file is read + trimmed.
func TestReadSidecarToken_HappyPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allow.yaml.token")
	want := "abc123"
	if err := os.WriteFile(path, []byte(want+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readSidecarToken(path)
	if err != nil {
		t.Fatalf("readSidecarToken: %v", err)
	}
	if got != want {
		t.Errorf("token = %q, want %q (whitespace must be trimmed)", got, want)
	}
}

// TestReadSidecarToken_RejectsLooseMode — 0644 is rejected.
func TestReadSidecarToken_RejectsLooseMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allow.yaml.token")
	if err := os.WriteFile(path, []byte("abc"), 0o644); err != nil { //nolint:gosec // G306 — intentional: this test verifies that readSidecarToken REJECTS 0o644 (loose-mode token files leak via mode-bit observation in shared filesystems).
		t.Fatal(err)
	}
	_, err := readSidecarToken(path)
	if err == nil {
		t.Fatal("readSidecarToken on 0644 file: want error, got nil")
	}
	if !strings.Contains(err.Error(), "0600") {
		t.Errorf("error = %q; want mention of 0600 + chmod hint", err.Error())
	}
}

// TestReadSidecarToken_MissingFile — non-existent path errors.
func TestReadSidecarToken_MissingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nope.token")
	_, err := readSidecarToken(path)
	if err == nil {
		t.Fatal("readSidecarToken on missing file: want error, got nil")
	}
}

// TestPerformReload_RequiresAllowFile — performReload errors
// when allowFile is empty.
func TestPerformReload_RequiresAllowFile(t *testing.T) {
	r := newReloadableHandler(&stubGatedHandler{id: "v1"})
	opts := proxyListenOpts{} // no allowFile
	err := performReload(context.Background(), &nopPrinter{}, opts, nil, r)
	if err == nil {
		t.Fatal("performReload without --allow-file: want error, got nil")
	}
	if !strings.Contains(err.Error(), "--reload-allow-file requires --allow-file") {
		t.Errorf("error = %q; want mention of --reload-allow-file requirement", err.Error())
	}
}

// TestValidateProxyListenOpts_ReloadRequiresAllowFile — the
// CLI-validation layer rejects --reload-allow-file without
// --allow-file.
func TestValidateProxyListenOpts_ReloadRequiresAllowFile(t *testing.T) {
	opts := proxyListenOpts{
		target:          "host:443",
		listen:          "127.0.0.1:1443",
		acceptWrites:    true,
		confirmTarget:   "host:443",
		confirmToken:    "tok",
		ppFile:          "/tmp/pp",
		reloadAllowFile: true,
		// allowFile intentionally empty.
	}
	err := validateProxyListenOpts(opts)
	if err == nil {
		t.Fatal("want error for --reload-allow-file without --allow-file")
	}
	if !strings.Contains(err.Error(), "--reload-allow-file requires --allow-file") {
		t.Errorf("error = %q; want explanatory message", err.Error())
	}
}

// TestFreshReloadOpts_PreservesImmutables — the reload helper
// keeps target/listen/timeouts but clears plugin-specific
// allowlist fields. Pin the contract.
func TestFreshReloadOpts_PreservesImmutables(t *testing.T) {
	original := proxyListenOpts{
		plugin:        "sip",
		target:        "pbx:5060",
		listen:        "127.0.0.1:5060",
		allowFile:     "/etc/elsereno/sip-gate.yaml",
		acceptWrites:  true,
		confirmTarget: "pbx:5060",
		ppFile:        "/etc/elsereno/dev.pp",
		methods:       []string{"INVITE", "REGISTER"}, // plugin-specific; should be cleared
	}
	fresh := freshReloadOpts(original)
	if fresh.plugin != "sip" || fresh.target != "pbx:5060" || fresh.listen != "127.0.0.1:5060" ||
		fresh.allowFile != "/etc/elsereno/sip-gate.yaml" || fresh.acceptWrites != true ||
		fresh.confirmTarget != "pbx:5060" || fresh.ppFile != "/etc/elsereno/dev.pp" {
		t.Errorf("freshReloadOpts dropped an immutable field: %+v", fresh)
	}
	if len(fresh.methods) != 0 {
		t.Errorf("fresh.methods = %v; want empty (plugin-specific lists must be cleared for re-load)", fresh.methods)
	}
}

// nopPrinter satisfies cmdPrinter without doing anything.
type nopPrinter struct{}

func (n *nopPrinter) Printf(_ string, _ ...any) {}

// TestWrapForReload_OptOut — when --reload-allow-file is not
// set, wrapForReload returns the handler unchanged (no
// wrapper, byte-identical to pre-v1.17 behaviour).
func TestWrapForReload_OptOut(t *testing.T) {
	h := &stubGatedHandler{id: "v1"}
	got := wrapForReload(proxyListenOpts{reloadAllowFile: false}, h)
	if got != gatedProxyHandler(h) {
		t.Error("wrapForReload(reloadAllowFile=false) wrapped the handler; expected pass-through")
	}
}

// TestWrapForReload_OptIn — when --reload-allow-file is set,
// wrapForReload returns a *reloadableHandler.
func TestWrapForReload_OptIn(t *testing.T) {
	h := &stubGatedHandler{id: "v1"}
	got := wrapForReload(proxyListenOpts{reloadAllowFile: true}, h)
	if _, ok := got.(*reloadableHandler); !ok {
		t.Errorf("wrapForReload(reloadAllowFile=true) = %T; want *reloadableHandler", got)
	}
}

// TestReloadableHandler_HandleWithNilInnerErrors — defensive:
// a wrapper without an installed inner returns a typed error
// (don't NPE).
func TestReloadableHandler_HandleWithNilInnerErrors(t *testing.T) {
	r := &reloadableHandler{} // no inner installed
	err := r.Handle(context.Background(), nil, nil)
	if err == nil {
		t.Fatal("Handle() with nil inner: want error, got nil")
	}
	if !errors.Is(err, errors.New("reloadable: nil handler")) && !strings.Contains(err.Error(), "nil") {
		t.Errorf("error = %q; want mention of nil handler", err.Error())
	}
}
