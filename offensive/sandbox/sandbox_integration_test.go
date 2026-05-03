//go:build offensive && linux && sandbox_integration

package sandbox

import (
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// These tests install a real seccomp-BPF filter on the current
// kernel and verify the expected syscalls are blocked with EPERM.
// They run only under the `sandbox_integration` build tag so
// developer machines without a cooperating kernel + container
// runtime don't trip on environment quirks (Docker Desktop's
// Rosetta/QEMU amd64 emulation, older kernels, outer seccomp
// profiles). CI on Linux amd64 / arm64 runs them via
// `make sandbox-integration`.

// TestLoad_ExploitInstallsFilter covers the happy path: Load
// returns Available=true with Kind="seccomp-bpf" on a kernel that
// accepts the filter.
func TestLoad_ExploitInstallsFilter(t *testing.T) {
	// The install-filter path is irreversible per-thread, so we
	// run it in a subprocess the test forks via `-run`. The
	// subprocess is this same binary, identified by an env var.
	if os.Getenv("ELSERENO_SANDBOX_INTEGRATION_CHILD") == "1" {
		res, err := Load(ProfileExploit)
		if err != nil {
			_, _ = os.Stderr.WriteString("LOAD_ERR:" + err.Error())
			os.Exit(3)
		}
		if !res.Availability.Available {
			_, _ = os.Stderr.WriteString("NOT_AVAILABLE:" + res.Availability.Reason)
			os.Exit(4)
		}
		if res.Availability.Kind != "seccomp-bpf" {
			_, _ = os.Stderr.WriteString("UNEXPECTED_KIND:" + res.Availability.Kind)
			os.Exit(5)
		}
		os.Exit(0)
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestLoad_ExploitInstallsFilter") // #nosec G204 -- re-exec of this test binary
	cmd.Env = append(os.Environ(), "ELSERENO_SANDBOX_INTEGRATION_CHILD=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child failed: %v\noutput:\n%s", err, out)
	}
}

// TestLoad_ExploitBlocksPtrace: after installing the exploit
// profile, a ptrace call must return EPERM. This proves the
// filter actually took effect (not just that installFilter
// returned without error).
func TestLoad_ExploitBlocksPtrace(t *testing.T) {
	if os.Getenv("ELSERENO_SANDBOX_BLOCK_CHILD") == "1" {
		if _, err := Load(ProfileExploit); err != nil {
			_, _ = os.Stderr.WriteString("LOAD_ERR:" + err.Error())
			os.Exit(3)
		}
		// Try ptrace — must return EPERM.
		_, _, errno := unix.Syscall6(unix.SYS_PTRACE, uintptr(unix.PTRACE_TRACEME), 0, 0, 0, 0, 0)
		if errors.Is(errno, unix.EPERM) {
			os.Exit(0)
		}
		_, _ = os.Stderr.WriteString("UNEXPECTED_ERRNO:" + errno.Error())
		os.Exit(6)
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestLoad_ExploitBlocksPtrace") // #nosec G204 -- re-exec
	cmd.Env = append(os.Environ(), "ELSERENO_SANDBOX_BLOCK_CHILD=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(string(out), "UNEXPECTED_ERRNO") {
			t.Fatalf("ptrace not blocked: %s", out)
		}
		t.Fatalf("child failed: %v\noutput:\n%s", err, out)
	}
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skipf("arch %s not covered by integration filter table", runtime.GOARCH)
	}
}

// TestLoad_DialBlocksConnect: after installing dial profile, a
// call to socket+connect must hit EPERM on socket, proving the
// network-path denylist is effective.
func TestLoad_DialBlocksConnect(t *testing.T) {
	if os.Getenv("ELSERENO_SANDBOX_DIAL_CHILD") == "1" {
		if _, err := Load(ProfileDial); err != nil {
			_, _ = os.Stderr.WriteString("LOAD_ERR:" + err.Error())
			os.Exit(3)
		}
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
		if err == unix.EPERM {
			os.Exit(0)
		}
		if err != nil {
			_, _ = os.Stderr.WriteString("UNEXPECTED_SOCK_ERR:" + err.Error())
			os.Exit(7)
		}
		_ = unix.Close(fd)
		_, _ = os.Stderr.WriteString("SOCKET_CALL_SUCCEEDED")
		os.Exit(8)
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestLoad_DialBlocksConnect") // #nosec G204 -- re-exec
	cmd.Env = append(os.Environ(), "ELSERENO_SANDBOX_DIAL_CHILD=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child failed: %v\noutput:\n%s", err, out)
	}
}
