package creds_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"local/elsereno/internal/creds"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.v1.bin")

	v := creds.New()
	if err := v.InitToFile(ctx, []byte("pp"), path); err != nil {
		t.Fatalf("InitToFile: %v", err)
	}
	if err := v.Store(ctx, "shodan", []byte("sec")); err != nil {
		t.Fatalf("Store: %v", err)
	}
	if err := v.SaveToFile(path); err != nil {
		t.Fatalf("SaveToFile: %v", err)
	}

	v2 := creds.New()
	if err := v2.LoadFromFile(path); err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}
	if !v2.Status().Initialised || v2.Status().Unlocked {
		t.Fatalf("status = %+v; want init but locked", v2.Status())
	}
	if err := v2.Unlock(ctx, []byte("pp")); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	got, err := v2.Retrieve(ctx, "shodan")
	if err != nil {
		t.Fatalf("Retrieve: %v", err)
	}
	if string(got) != "sec" {
		t.Fatalf("Retrieve = %q, want %q", got, "sec")
	}
}

func TestInitToFileRefusesOverwrite(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.v1.bin")

	v := creds.New()
	if err := v.InitToFile(ctx, []byte("pp"), path); err != nil {
		t.Fatalf("InitToFile first: %v", err)
	}

	v2 := creds.New()
	err := v2.InitToFile(ctx, []byte("pp"), path)
	if !errors.Is(err, creds.ErrFileExists) {
		t.Fatalf("second InitToFile: got %v, want ErrFileExists", err)
	}
}
