//go:build !windows

package main

import (
	"fmt"
	"syscall"
)

// checkDisk reports free bytes in the cwd's filesystem via
// syscall.Statfs (unix variants).
func checkDisk() doctorResult {
	var st syscall.Statfs_t
	if err := syscall.Statfs(".", &st); err != nil {
		return doctorResult{name: "disk", status: doctorWarn, message: err.Error()}
	}
	// Bytes free in the current filesystem. Statfs field types differ
	// by platform (darwin: Bavail uint64, Bsize uint32; linux: Bavail
	// uint64, Bsize int64). Explicit uint64 conversions normalise both.
	//
	//nolint:unconvert // cross-platform widening; one side may already be uint64
	free := uint64(st.Bavail) * uint64(st.Bsize) // #nosec G115 -- cross-platform widening
	const oneGiB = uint64(1 << 30)
	if free < oneGiB {
		return doctorResult{name: "disk", status: doctorFail, message: fmt.Sprintf("only %d MiB free in %q", free>>20, ".")}
	}
	return doctorResult{name: "disk", status: doctorOK, message: fmt.Sprintf("%d MiB free", free>>20)}
}
