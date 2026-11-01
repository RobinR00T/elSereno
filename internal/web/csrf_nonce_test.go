package web

import (
	"bytes"
	"context"
	"testing"

	"local/elsereno/internal/config"
	"local/elsereno/internal/creds"
)

// TestNewServer_DerivesCSRFKey pins L3: NewServer derives a 32-byte,
// non-zero CSRF key from the vault. The key is held for the
// not-yet-wired cookie/CSRF middleware (PITF-087); this test is its
// only reader, so removing the derivation fails loudly here.
func TestNewServer_DerivesCSRFKey(t *testing.T) {
	vault := creds.New()
	if err := vault.Init(context.Background(), []byte("csrf-key-test")); err != nil {
		t.Fatalf("vault init: %v", err)
	}
	srv, err := NewServer(Options{Addr: "127.0.0.1:0", Web: config.Defaults().Web, Vault: vault})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if len(srv.csrfKey) != 32 {
		t.Fatalf("csrfKey len = %d, want 32", len(srv.csrfKey))
	}
	if bytes.Equal(srv.csrfKey, make([]byte, 32)) {
		t.Fatal("csrfKey is all-zero: the vault derivation did not run")
	}
}

// TestRandNonce_UniqueNonEmpty covers the happy path of L2: randNonce
// returns a non-empty value and surfaces no error; the fail-closed
// path (crypto/rand error) is exercised by code review, not here,
// because crypto/rand does not fail on supported platforms.
func TestRandNonce_UniqueNonEmpty(t *testing.T) {
	a, err := randNonce()
	if err != nil || a == "" {
		t.Fatalf("randNonce: %q %v", a, err)
	}
	b, err := randNonce()
	if err != nil {
		t.Fatalf("randNonce: %v", err)
	}
	if a == b {
		t.Fatal("randNonce returned identical values twice")
	}
}
