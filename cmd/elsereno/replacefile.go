package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// replaceFile writes data to path as a new file with the given mode,
// whatever was there before: a temp file in the same directory,
// chmod'ed to mode and renamed over path. os.WriteFile applies its mode
// only when it creates the file, so overwriting a 0644 allow-file or
// vault left it 0644 while the command said 0600 (PITF-093).
//
// A symlink at path is refused, not followed or replaced: replacing it
// would leave its target with the old contents. A hard link to path
// keeps the old contents under its other name. The directory must be
// writable, and the new file belongs to whoever runs the command.
func replaceFile(path string, data []byte, mode os.FileMode) error {
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink; write to the file it points to", path)
	}
	// CreateTemp opens the file 0600, so the new contents are never
	// readable by others before the chmod.
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	fail := func(err error) error {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		return fail(err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}
