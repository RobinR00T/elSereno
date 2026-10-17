package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestReplaceFile_ExistingFileGetsMode: an existing 0644 file ends up
// with the requested mode and the new contents. os.WriteFile kept the
// 0644 (PITF-093).
func TestReplaceFile_ExistingFileGetsMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.v1.bin")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil { // #nosec G302 -- the 0644 file is the defect under test
		t.Fatal(err)
	}
	if err := replaceFile(path, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %#o, want 0600", fi.Mode().Perm())
	}
	if b, _ := os.ReadFile(path); string(b) != "new" { // #nosec G304 -- test tempdir path
		t.Fatalf("contents = %q", b)
	}
	assertOnlyFiles(t, dir, "vault.v1.bin")

	// backup restore passes the mode recorded in the archive.
	if err := replaceFile(path, []byte("newer"), 0o640); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode after second write = %v (%v), want 0640", fi.Mode().Perm(), err)
	}
}

// TestReplaceFile_RefusesSymlink: a symlink at the path is refused and
// neither it nor its target changes.
func TestReplaceFile_RefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.yaml")
	link := filepath.Join(dir, "allow.yaml")
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink: %v", err)
	}
	if err := replaceFile(link, []byte("new"), 0o600); err == nil {
		t.Fatal("replaceFile wrote through a symlink")
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("symlink replaced: %v %v", fi, err)
	}
	if b, _ := os.ReadFile(target); string(b) != "old" { // #nosec G304 -- test tempdir path
		t.Fatalf("target contents = %q", b)
	}
	assertOnlyFiles(t, dir, "allow.yaml", "real.yaml")
}

// TestReplaceFile_NoTempLeftOnError: a failed rename (the path is a
// directory) leaves no temp file behind.
func TestReplaceFile_NoTempLeftOnError(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "out"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := replaceFile(filepath.Join(dir, "out"), []byte("x"), 0o600); err == nil {
		t.Fatal("replaceFile over a directory succeeded")
	}
	assertOnlyFiles(t, dir, "out")
}

func assertOnlyFiles(t *testing.T, dir string, want ...string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(want) {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("dir holds %q, want %q", names, want)
	}
}
