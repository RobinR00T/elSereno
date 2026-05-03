package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadPassphraseFile_HappyPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pp")
	if err := os.WriteFile(path, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := loadPassphraseFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "secret" {
		t.Fatalf("got %q, want %q", got, "secret")
	}
}

func TestLoadPassphraseFile_StripsCRLF(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pp")
	if err := os.WriteFile(path, []byte("secret\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := loadPassphraseFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "secret" {
		t.Fatalf("got %q, want %q", got, "secret")
	}
}

func TestLoadPassphraseFile_RejectsGroupReadable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pp")
	if err := os.WriteFile(path, []byte("secret"), 0o640); err != nil { // #nosec G306 -- test deliberately writes a lax-mode file to verify rejection
		t.Fatal(err)
	}
	_, err := loadPassphraseFile(path)
	if !errors.Is(err, ErrPassphraseFileMode) {
		t.Fatalf("want ErrPassphraseFileMode, got %v", err)
	}
}

func TestLoadPassphraseFile_RejectsWorldReadable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pp")
	if err := os.WriteFile(path, []byte("secret"), 0o644); err != nil { // #nosec G306 -- test deliberately writes a lax-mode file to verify rejection
		t.Fatal(err)
	}
	_, err := loadPassphraseFile(path)
	if !errors.Is(err, ErrPassphraseFileMode) {
		t.Fatalf("want ErrPassphraseFileMode, got %v", err)
	}
}

func TestLoadPassphraseFile_EmptyRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pp")
	if err := os.WriteFile(path, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := loadPassphraseFile(path)
	if err == nil {
		t.Fatal("expected error on empty file")
	}
}

func TestLoadPassphraseFile_RejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}
	_, err := loadPassphraseFile(link)
	if !errors.Is(err, ErrPassphraseFileNotRegular) {
		t.Fatalf("want ErrPassphraseFileNotRegular, got %v", err)
	}
}

func TestLoadPassphraseFile_MissingPath(t *testing.T) {
	_, err := loadPassphraseFile("/nonexistent/path/nope")
	if err == nil {
		t.Fatal("expected stat error")
	}
}

func TestLoadPassphraseFile_OnlyOwnerExecPermittedAsWell(t *testing.T) {
	// 0500 should pass (read for user, no read elsewhere) — tests
	// the mask-out check is correct, not a loose == 0600.
	dir := t.TempDir()
	path := filepath.Join(dir, "pp")
	if err := os.WriteFile(path, []byte("secret"), 0o500); err != nil { // #nosec G306 -- 0500 is intentionally tight; Chmod immediately below narrows further.
		t.Fatal(err)
	}
	// #nosec G302 -- test fixture, 0500 is deliberately restrictive.
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPassphraseFile(path); err != nil {
		t.Fatalf("0400 should load cleanly: %v", err)
	}
}
