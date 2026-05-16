package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"local/elsereno/internal/core"
)

func newDoctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Run cross-platform preflight checks",
		RunE: func(cmd *cobra.Command, _ []string) error {
			results := runDoctor()
			failed := 0
			for _, r := range results {
				cmd.Println(r.String())
				if r.status == doctorFail {
					failed++
				}
			}
			cmd.Printf("\n%d checks, %d failed\n", len(results), failed)
			if failed > 0 {
				return fail(core.ExitUnavail, fmt.Errorf("%d doctor checks failed", failed))
			}
			return nil
		},
	}
}

type doctorStatus string

const (
	doctorOK   doctorStatus = "ok"
	doctorWarn doctorStatus = "warn"
	doctorFail doctorStatus = "fail"
	doctorSkip doctorStatus = "skip"
)

type doctorResult struct {
	name    string
	status  doctorStatus
	message string
}

func (r doctorResult) String() string {
	sym := map[doctorStatus]string{
		doctorOK:   "[OK]",
		doctorWarn: "[WARN]",
		doctorFail: "[FAIL]",
		doctorSkip: "[SKIP]",
	}[r.status]
	if r.message == "" {
		return fmt.Sprintf("%-7s %s", sym, r.name)
	}
	return fmt.Sprintf("%-7s %s — %s", sym, r.name, r.message)
}

// runDoctor performs the preflight checks that have no external
// dependencies. Full checks (Postgres, nmap, Shodan/Censys endpoints,
// NTP drift, memguard mlock) are added in later F1 chunks once the
// relevant adapters are wired.
func runDoctor() []doctorResult {
	var out []doctorResult

	out = append(out, checkGoRuntime())
	out = append(out, checkPlatform())
	out = append(out, checkPrivilegedScan())
	out = append(out, checkNmap())
	out = append(out, checkIPv6())
	out = append(out, checkDisk())

	return out
}

func checkGoRuntime() doctorResult {
	return doctorResult{
		name:    "go runtime",
		status:  doctorOK,
		message: runtime.Version(),
	}
}

func checkPlatform() doctorResult {
	return doctorResult{
		name:    "platform",
		status:  doctorOK,
		message: fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
	}
}

func checkNmap() doctorResult {
	path, err := exec.LookPath("nmap")
	if err != nil {
		return doctorResult{
			name:    "nmap",
			status:  doctorWarn,
			message: "not found on PATH; scan requires nmap >= 7.80",
		}
	}
	return doctorResult{
		name:    "nmap",
		status:  doctorOK,
		message: path,
	}
}

// checkPrivilegedScan reports whether the current process can do raw-socket
// scans. Linux: CAP_NET_RAW; macOS: euid==0. When missing, a warning
// points at the connect-scan fallback.
func checkPrivilegedScan() doctorResult {
	switch runtime.GOOS {
	case "linux":
		// Reading /proc/self/status for CapEff is pragmatic; no extra deps.
		data, err := os.ReadFile("/proc/self/status")
		if err != nil {
			return doctorResult{name: "privileged scan", status: doctorWarn, message: err.Error()}
		}
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "CapEff:") {
				// CAP_NET_RAW is bit 13 (0x2000). Conservative string
				// match avoids parsing hex for this scaffold.
				if strings.Contains(line, "0000000000002000") ||
					strings.Contains(line, "ffffffffffffffff") {
					return doctorResult{name: "privileged scan", status: doctorOK, message: "CAP_NET_RAW present"}
				}
				return doctorResult{
					name:    "privileged scan",
					status:  doctorWarn,
					message: "CAP_NET_RAW missing — use nmap -sT or `sudo setcap cap_net_raw=+ep $(which nmap)`",
				}
			}
		}
		return doctorResult{name: "privileged scan", status: doctorWarn, message: "cannot determine capabilities"}
	case "darwin":
		if syscall.Geteuid() == 0 {
			return doctorResult{name: "privileged scan", status: doctorOK, message: "running as root"}
		}
		return doctorResult{
			name:    "privileged scan",
			status:  doctorWarn,
			message: "not root — use nmap -sT for unprivileged scans",
		}
	default:
		return doctorResult{name: "privileged scan", status: doctorSkip, message: "only linux/darwin are supported in v1"}
	}
}

func checkIPv6() doctorResult {
	ifaces, err := net.InterfaceAddrs()
	if err != nil {
		return doctorResult{name: "ipv6", status: doctorWarn, message: err.Error()}
	}
	for _, a := range ifaces {
		if ip, ok := a.(*net.IPNet); ok && ip.IP.To4() == nil && ip.IP.To16() != nil {
			return doctorResult{name: "ipv6", status: doctorOK, message: "at least one IPv6 address present"}
		}
	}
	return doctorResult{name: "ipv6", status: doctorWarn, message: "no IPv6 address on any interface"}
}

// checkDisk lives in cmd_doctor_disk_unix.go (linux + darwin)
// and cmd_doctor_disk_windows.go (v2.34+ stub) so the Windows
// build doesn't pull in syscall.Statfs.
