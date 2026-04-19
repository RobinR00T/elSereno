package creds_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"local/elsereno/internal/creds"
)

func TestVaultLifecycle(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	v := creds.New()
	if v.Status().Initialised {
		t.Fatal("fresh vault should not be initialised")
	}

	if err := v.Init(ctx, []byte("correct horse battery staple")); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if !v.Status().Initialised || !v.Status().Unlocked {
		t.Fatalf("status = %+v; want {init, unlocked}", v.Status())
	}

	if err := v.Store(ctx, "shodan", []byte("secret-api-key")); err != nil {
		t.Fatalf("Store: %v", err)
	}

	got, err := v.Retrieve(ctx, "shodan")
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	if string(got) != "secret-api-key" {
		t.Fatalf("Retrieve = %q, want %q", got, "secret-api-key")
	}

	// Lock then unlock.
	v.Lock()
	if v.Status().Unlocked {
		t.Fatal("Lock should clear unlocked")
	}
	if err := v.Store(ctx, "x", []byte("y")); !errors.Is(err, creds.ErrLocked) {
		t.Fatalf("Store on locked = %v, want ErrLocked", err)
	}
	if err := v.Unlock(ctx, []byte("correct horse battery staple")); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
}

func TestVaultBadPassphrase(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	v := creds.New()
	if err := v.Init(ctx, []byte("right-one")); err != nil {
		t.Fatalf("Init: %v", err)
	}
	state := captureState(t, v)

	v2 := creds.New()
	v2.Load(state)
	if err := v2.Unlock(ctx, []byte("wrong-one")); !errors.Is(err, creds.ErrBadPassphrase) {
		t.Fatalf("Unlock(bad) = %v, want ErrBadPassphrase", err)
	}
	if err := v2.Unlock(ctx, []byte("right-one")); err != nil {
		t.Fatalf("Unlock(right): %v", err)
	}
}

func TestVaultDeriveRequiresUnlock(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	v := creds.New()
	if err := v.Init(ctx, []byte("pp")); err != nil {
		t.Fatalf("Init: %v", err)
	}
	out := make([]byte, 32)
	if err := v.Derive("elsereno/csrf/v1", out); err != nil {
		t.Fatalf("Derive: %v", err)
	}
	zero := make([]byte, 32)
	if bytes.Equal(out, zero) {
		t.Fatal("Derive produced zeros")
	}
	v.Lock()
	if err := v.Derive("elsereno/csrf/v1", out); !errors.Is(err, creds.ErrLocked) {
		t.Fatalf("Derive after Lock = %v, want ErrLocked", err)
	}
}

func TestVaultInitRejectsReinitialise(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	v := creds.New()
	if err := v.Init(ctx, []byte("pp")); err != nil {
		t.Fatalf("Init: %v", err)
	}
	err := v.Init(ctx, []byte("different"))
	if !errors.Is(err, creds.ErrAlreadyInitialised) {
		t.Fatalf("re-init: got %v, want ErrAlreadyInitialised", err)
	}
}

func TestVaultStoreRotatePurge(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	v := creds.New()
	_ = v.Init(ctx, []byte("pp"))

	if err := v.Store(ctx, "n", []byte("v1")); err != nil {
		t.Fatal(err)
	}
	md, err := v.Metadata("n")
	if err != nil {
		t.Fatal(err)
	}
	if md.Name != "n" {
		t.Fatalf("name=%q", md.Name)
	}
	if err := v.Rotate(ctx, "n", []byte("v2")); err != nil {
		t.Fatal(err)
	}
	got, _ := v.Retrieve(ctx, "n")
	if string(got) != "v2" {
		t.Fatalf("after rotate: %q", got)
	}
	if err := v.Purge(ctx, "n"); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Retrieve(ctx, "n"); !errors.Is(err, creds.ErrNameNotFound) {
		t.Fatalf("after purge: %v", err)
	}
}

// captureState exposes VaultState via the Envelope escape hatch for
// round-tripping in tests. In production the storage adapter writes to
// disk; here we re-encode via the public VaultState type.
func captureState(t *testing.T, v *creds.Vault) creds.VaultState {
	t.Helper()
	// Re-export not implemented in chunk 2; use reflect against
	// Envelope which returns hex-encoded bytes. A cleaner API will land
	// alongside the file-backed storage adapter.
	// For now, Init+Store lives in-process. This helper reconstructs a
	// parallel state by running Init on a sibling and returning its
	// VaultState via a friend-style accessor below.
	return v.SnapshotForTesting()
}
