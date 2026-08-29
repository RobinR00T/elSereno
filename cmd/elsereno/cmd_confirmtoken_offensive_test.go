//go:build offensive

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// The confirm-token can come from --confirm-token or a 0600
// --confirm-token-file (so it does not leak via ps / shell history).
func TestResolveConfirmToken(t *testing.T) {
	// Flag only: passthrough.
	if got, err := resolveConfirmToken("tok", ""); err != nil || got != "tok" {
		t.Fatalf("flag only: got %q err %v", got, err)
	}
	// Both set: mutually exclusive.
	if _, err := resolveConfirmToken("tok", "/nonexistent"); err == nil {
		t.Fatal("both flag and file: want mutually-exclusive error")
	}
	// File 0600: read and trim trailing newline.
	dir := t.TempDir()
	p := filepath.Join(dir, "tok")
	if err := os.WriteFile(p, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := resolveConfirmToken("", p); err != nil || got != "secret" {
		t.Fatalf("file: got %q err %v", got, err)
	}
	// File with loose perms: rejected by the 0600 guard.
	loose := filepath.Join(dir, "loose")
	if err := os.WriteFile(loose, []byte("x"), 0o644); err != nil { //nolint:gosec // deliberately loose to exercise the 0600 guard
		t.Fatal(err)
	}
	if _, err := resolveConfirmToken("", loose); err == nil {
		t.Fatal("loose perms: want error")
	}
}
