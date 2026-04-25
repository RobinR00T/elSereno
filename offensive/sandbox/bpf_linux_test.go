//go:build offensive && linux

package sandbox

import (
	"runtime"
	"testing"

	"golang.org/x/sys/unix"
)

// assertFilterShape checks the static layout a denylist filter
// must have: 4 prologue instructions (LD arch, JEQ arch, RET KILL,
// LD nr) + one JEQ per blocked syscall + 2 tail returns (RET ALLOW
// and RET ERRNO|EPERM). Total = 6 + blocked.
func assertFilterShape(t *testing.T, prog []unix.SockFilter, wantBlockedCount int) {
	t.Helper()
	wantLen := 6 + wantBlockedCount
	if len(prog) != wantLen {
		t.Fatalf("program length = %d, want %d (blocked=%d)", len(prog), wantLen, wantBlockedCount)
	}

	// Prologue: LD arch / JEQ audit_arch / RET KILL / LD nr.
	if prog[0].Code != (bpfLD|bpfW|bpfABS) || prog[0].K != seccompDataOffsetArch {
		t.Fatalf("insn[0] = %+v; want LD [arch]", prog[0])
	}
	if prog[1].Code != (bpfJMP | bpfJEQ | bpfK) {
		t.Fatalf("insn[1].Code = 0x%x; want JEQ", prog[1].Code)
	}
	if prog[2].Code != (bpfRET|bpfK) || prog[2].K != seccompRetKill {
		t.Fatalf("insn[2] = %+v; want RET KILL", prog[2])
	}
	if prog[3].Code != (bpfLD|bpfW|bpfABS) || prog[3].K != seccompDataOffsetNR {
		t.Fatalf("insn[3] = %+v; want LD [nr]", prog[3])
	}

	// Every JEQ in the body must jump Jt offsets that land on the
	// last instruction (RET ERRNO).
	retErrnoIdx := uint8(len(prog) - 1)
	for i := 0; i < wantBlockedCount; i++ {
		ins := prog[4+i]
		if ins.Code != (bpfJMP | bpfJEQ | bpfK) {
			t.Fatalf("insn[%d].Code = 0x%x; want JEQ", 4+i, ins.Code)
		}
		// Jt is pc-relative from the NEXT instruction, so the
		// effective target index is (4+i) + 1 + Jt.
		target := uint8(4+i) + 1 + ins.Jt
		if target != retErrnoIdx {
			t.Fatalf("insn[%d] Jt target = %d, want %d (retErrno)", 4+i, target, retErrnoIdx)
		}
	}

	// Tail RET ALLOW + RET ERRNO.
	allow := prog[len(prog)-2]
	if allow.Code != (bpfRET|bpfK) || allow.K != seccompRetAllow {
		t.Fatalf("allow tail = %+v; want RET ALLOW", allow)
	}
	deny := prog[len(prog)-1]
	if deny.Code != (bpfRET|bpfK) || deny.K != (seccompRetErrno|uint32(unix.EPERM)) {
		t.Fatalf("deny tail = %+v; want RET ERRNO|EPERM", deny)
	}
}

func TestFilterProgram_Exploit(t *testing.T) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skipf("no syscall table for %s", runtime.GOARCH)
	}
	prog, err := FilterProgram(ProfileExploit)
	if err != nil {
		t.Fatal(err)
	}
	// Exploit's denylist = base blocklist. Exact size depends on
	// per-arch non-zero entries (arm64 generic drops fork/vfork).
	_, nums, _ := archFor(runtime.GOARCH)
	want := len(blockedSyscalls(ProfileExploit, nums))
	if want == 0 {
		t.Fatal("exploit profile produced empty blocklist — ADR-042 violation")
	}
	assertFilterShape(t, prog, want)
}

func TestFilterProgram_HarvestAddsFileMutators(t *testing.T) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skipf("no syscall table for %s", runtime.GOARCH)
	}
	exploitProg, _ := FilterProgram(ProfileExploit)
	harvestProg, _ := FilterProgram(ProfileHarvest)
	if len(harvestProg) <= len(exploitProg) {
		t.Fatalf("harvest blocklist (%d) must be strictly larger than exploit (%d)",
			len(harvestProg), len(exploitProg))
	}
}

func TestFilterProgram_DialAddsNetworkOpeners(t *testing.T) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skipf("no syscall table for %s", runtime.GOARCH)
	}
	exploitProg, _ := FilterProgram(ProfileExploit)
	dialProg, _ := FilterProgram(ProfileDial)
	if len(dialProg) <= len(exploitProg) {
		t.Fatalf("dial blocklist (%d) must be strictly larger than exploit (%d)",
			len(dialProg), len(exploitProg))
	}
	// Dial MUST block SYS_connect specifically.
	_, nums, _ := archFor(runtime.GOARCH)
	connect := nums.Connect
	found := false
	for _, ins := range dialProg {
		if ins.K == connect && (ins.Code&(bpfJMP|bpfJEQ|bpfK)) == (bpfJMP|bpfJEQ|bpfK) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("dial profile must block SYS_connect (nr=%d) — ADR-042 dial profile", connect)
	}
}

func TestFilterProgram_UnknownArchReturnsTypedError(t *testing.T) {
	_, _, err := archFor("s390x")
	if err == nil {
		t.Fatal("expected ErrArchUnsupported for s390x")
	}
	if err != ErrArchUnsupported {
		t.Fatalf("want ErrArchUnsupported, got %v", err)
	}
}

func TestBlockedSyscalls_DedupesAndDropsZeros(t *testing.T) {
	// A fake table with zeros + duplicates to ensure the pipeline
	// is honest about both conditions.
	fake := syscallNums{
		Execve:   59,
		Execveat: 59, // dup
		Fork:     0,  // unsupported on this arch
		Ptrace:   101,
	}
	out := blockedSyscalls(ProfileExploit, fake)
	var sawZero bool
	seen := map[uint32]int{}
	for _, v := range out {
		seen[v]++
		if v == 0 {
			sawZero = true
		}
	}
	if sawZero {
		t.Fatal("filter contains syscall nr=0 — would accidentally block read()")
	}
	for v, n := range seen {
		if n > 1 {
			t.Fatalf("syscall %d appears %d times; must be unique", v, n)
		}
	}
}
