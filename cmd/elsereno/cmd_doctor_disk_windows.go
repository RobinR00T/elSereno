//go:build windows

package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

// checkDisk reports free bytes in the cwd's filesystem via
// GetDiskFreeSpaceExW (Windows).
//
// We avoid pulling in golang.org/x/sys/windows by calling
// kernel32.dll directly through syscall.LazyDLL — keeps the
// Windows mini build dependency-light.
//
//nolint:gocritic // the LazyDLL trampoline is the idiomatic
// pattern for one-shot Windows API calls without x/sys.
func checkDisk() doctorResult {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	proc := kernel32.NewProc("GetDiskFreeSpaceExW")
	pathPtr, err := syscall.UTF16PtrFromString(".")
	if err != nil {
		return doctorResult{name: "disk", status: doctorWarn, message: err.Error()}
	}
	var (
		freeBytesAvailable     uint64
		totalNumberOfBytes     uint64
		totalNumberOfFreeBytes uint64
	)
	r1, _, callErr := proc.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(unsafe.Pointer(&freeBytesAvailable)),
		uintptr(unsafe.Pointer(&totalNumberOfBytes)),
		uintptr(unsafe.Pointer(&totalNumberOfFreeBytes)),
	)
	if r1 == 0 {
		// Call failed; surface the Windows error.
		return doctorResult{name: "disk", status: doctorWarn, message: callErr.Error()}
	}
	const oneGiB = uint64(1 << 30)
	if freeBytesAvailable < oneGiB {
		return doctorResult{name: "disk", status: doctorFail,
			message: fmt.Sprintf("only %d MiB free in %q", freeBytesAvailable>>20, ".")}
	}
	return doctorResult{name: "disk", status: doctorOK,
		message: fmt.Sprintf("%d MiB free", freeBytesAvailable>>20)}
}
