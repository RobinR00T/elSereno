//go:build offensive && linux

package sandbox

import (
	"runtime"
	"testing"

	"golang.org/x/sys/unix"
)

func TestNewArgDenyEqual_StoresValues(t *testing.T) {
	r := NewArgDenyEqual(42, 1, 0xAA, 0xBB)
	if r.Syscall != 42 {
		t.Errorf("Syscall = %d, want 42", r.Syscall)
	}
	if r.ArgIndex != 1 {
		t.Errorf("ArgIndex = %d, want 1", r.ArgIndex)
	}
	if len(r.EqualValues) != 2 || r.EqualValues[0] != 0xAA || r.EqualValues[1] != 0xBB {
		t.Errorf("EqualValues = %v, want [0xAA, 0xBB]", r.EqualValues)
	}
	if r.MaskBits != 0 {
		t.Errorf("MaskBits should be zero in equal-mode rule, got 0x%x", r.MaskBits)
	}
}

func TestNewArgDenyMaskAny_StoresMask(t *testing.T) {
	r := NewArgDenyMaskAny(257, 2, 0x0241)
	if r.MaskBits != 0x0241 {
		t.Errorf("MaskBits = 0x%x, want 0x0241", r.MaskBits)
	}
	if len(r.EqualValues) != 0 {
		t.Errorf("EqualValues should be empty in mask-mode, got %v", r.EqualValues)
	}
}

// countSyscall returns how many rules in rs scope to nr.
func countSyscall(rs []ArgDenyRule, nr uint32) int {
	n := 0
	for _, r := range rs {
		if r.Syscall == nr {
			n++
		}
	}
	return n
}

func TestArgFilterPresets_Amd64Tables(t *testing.T) {
	// On amd64 the preset union covers openat=257 (mask), open=2
	// (mask), socket=41 (equal) and clone=56 (mask) — four rules.
	rules := ArgFilterPresets(syscallsAMD64)
	if len(rules) != 4 {
		t.Fatalf("expected 4 preset rules (openat+open+socket+clone), got %d", len(rules))
	}
	for _, want := range []uint32{257, 2, 41, 56} {
		if countSyscall(rules, want) != 1 {
			t.Errorf("preset union missing syscall %d: %v", want, rules)
		}
	}
	for _, r := range rules {
		switch r.Syscall {
		case 257, 2: // openat / open — mask mode, must include O_WRONLY|O_RDWR
			if r.MaskBits&0x0003 == 0 {
				t.Errorf("syscall %d mask 0x%x missing O_WRONLY|O_RDWR", r.Syscall, r.MaskBits)
			}
		case 41: // socket — equal mode, AF_PACKET(17) + AF_NETLINK(16)
			gotPacket, gotNetlink := false, false
			for _, v := range r.EqualValues {
				switch v {
				case 17:
					gotPacket = true
				case 16:
					gotNetlink = true
				}
			}
			if !gotPacket || !gotNetlink {
				t.Errorf("socket preset missing AF_PACKET/AF_NETLINK: %v", r.EqualValues)
			}
		case 56: // clone — mask mode, must carry the namespace mask
			if r.MaskBits != cloneNewMask {
				t.Errorf("clone preset mask 0x%x, want cloneNewMask 0x%x", r.MaskBits, cloneNewMask)
			}
		}
	}
}

func TestSeccompDataArgOffset(t *testing.T) {
	cases := []struct {
		idx  uint8
		want uint32
	}{
		{0, 16},
		{1, 24},
		{2, 32},
		{3, 40},
		{4, 48},
		{5, 56},
	}
	for _, c := range cases {
		got := seccompDataArgOffset(c.idx)
		if got != c.want {
			t.Errorf("seccompDataArgOffset(%d) = %d, want %d", c.idx, got, c.want)
		}
	}
}

func TestArgRulesFor_PerProfile(t *testing.T) {
	// The clone-namespace rule is prepended to every profile; the
	// per-profile presets add on top.
	//
	//   Harvest / Scan → clone + openat + open  (3)
	//   Dial           → clone + socket         (2)
	//   Exploit        → clone                  (1)
	for _, tc := range []struct {
		p    Profile
		want int
		has  []uint32 // syscalls that must each appear once
	}{
		{ProfileHarvest, 3, []uint32{56, 257, 2}},
		{ProfileScan, 3, []uint32{56, 257, 2}},
		{ProfileDial, 2, []uint32{56, 41}},
		{ProfileExploit, 1, []uint32{56}},
	} {
		got := argRulesFor(tc.p, syscallsAMD64)
		if len(got) != tc.want {
			t.Errorf("%s len = %d, want %d (%v)", tc.p, len(got), tc.want, got)
		}
		for _, nr := range tc.has {
			if countSyscall(got, nr) != 1 {
				t.Errorf("%s missing syscall %d: %v", tc.p, nr, got)
			}
		}
	}
	// Dial's socket rule is equal-mode with AF_PACKET + AF_NETLINK.
	for _, r := range argRulesFor(ProfileDial, syscallsAMD64) {
		if r.Syscall == 41 && len(r.EqualValues) != 2 {
			t.Errorf("Dial socket EqualValues = %v, want 2 entries", r.EqualValues)
		}
	}
}

func TestArgRulesFor_UnknownProfileCloneOnly(t *testing.T) {
	// argRulesFor does not gate on profile validity (Load does that);
	// an unknown profile still gets the unconditional clone rule and
	// no per-profile preset.
	got := argRulesFor(Profile("bogus"), syscallsAMD64)
	if len(got) != 1 || got[0].Syscall != syscallsAMD64.Clone {
		t.Errorf("unknown profile rules = %v, want [clone only]", got)
	}
}

func TestCompileFilterWithArgs_NoRulesEqualsSyscallOnly(t *testing.T) {
	syscallOnly, err := FilterProgram(ProfileHarvest)
	if err != nil {
		t.Fatalf("FilterProgram: %v", err)
	}
	noArgs, err := CompileFilterWithArgs(ProfileHarvest, nil)
	if err != nil {
		t.Fatalf("CompileFilterWithArgs(nil): %v", err)
	}
	if len(noArgs) != len(syscallOnly) {
		t.Fatalf("nil rules should yield same length: got %d vs %d", len(noArgs), len(syscallOnly))
	}
	for i := range noArgs {
		if noArgs[i] != syscallOnly[i] {
			t.Fatalf("nil rules should equal FilterProgram at insn %d: %+v vs %+v", i, noArgs[i], syscallOnly[i])
		}
	}
}

func TestCompileFilterWithArgs_WeavesArgSection(t *testing.T) {
	syscallOnly, err := FilterProgram(ProfileHarvest)
	if err != nil {
		t.Fatalf("FilterProgram: %v", err)
	}
	combined, err := CompileFilterWithArgs(ProfileHarvest, argRulesFor(ProfileHarvest, syscallsAMD64))
	if err != nil {
		t.Fatalf("CompileFilterWithArgs: %v", err)
	}
	if len(combined) <= len(syscallOnly) {
		t.Fatalf("combined len %d should exceed syscall-only %d", len(combined), len(syscallOnly))
	}
}

func TestCompileFilterWithArgs_RejectsBadProfile(t *testing.T) {
	_, err := CompileFilterWithArgs(Profile("bogus"), nil)
	if err == nil {
		t.Fatal("expected error for unknown profile")
	}
}

// --- Runtime-verdict tests: a minimal cBPF interpreter ---------------
//
// A length-only check cannot tell a reachable denylist from a dead one,
// nor a deny jump that lands on RET ERRNO from one off by a single
// instruction onto RET ALLOW. These tests EXECUTE the compiled program
// against synthetic seccomp_data and assert the SECCOMP_RET_* verdict.

const (
	bpfALUOp uint16 = 0x04
	bpfANDOp uint16 = 0x50
)

// evalSeccomp interprets the opcode subset the sandbox emits
// (LD|W|ABS, ALU|AND|K, JMP|JEQ|K, RET|K) and returns the RET value.
func evalSeccomp(t *testing.T, prog []unix.SockFilter, arch, nr uint32, args [6]uint32) uint32 {
	t.Helper()
	mem := map[uint32]uint32{
		seccompDataOffsetNR:   nr,
		seccompDataOffsetArch: arch,
	}
	for i := uint8(0); i < 6; i++ {
		mem[seccompDataArgOffset(i)] = args[i]
	}
	var a uint32
	for pc := 0; pc < len(prog); {
		in := prog[pc]
		switch in.Code {
		case bpfLD | bpfW | bpfABS:
			v, ok := mem[in.K]
			if !ok {
				t.Fatalf("LD from unmapped offset %d at pc %d", in.K, pc)
			}
			a = v
			pc++
		case bpfALUOp | bpfANDOp | bpfK:
			a &= in.K
			pc++
		case bpfJMP | bpfJEQ | bpfK:
			if a == in.K {
				pc += 1 + int(in.Jt)
			} else {
				pc += 1 + int(in.Jf)
			}
		case bpfRET | bpfK:
			return in.K
		default:
			t.Fatalf("unknown opcode 0x%x at pc %d", in.Code, pc)
		}
		if pc < 0 || pc > len(prog) {
			t.Fatalf("jump out of range: pc=%d len=%d", pc, len(prog))
		}
	}
	t.Fatalf("program fell through without RET")
	return 0
}

func TestCombinedFilter_ArchCheckFirst(t *testing.T) {
	prog, err := CompileFilterWithArgs(ProfileHarvest, argRulesFor(ProfileHarvest, syscallsAMD64))
	if err != nil {
		t.Fatalf("CompileFilterWithArgs: %v", err)
	}
	if len(prog) < 4 {
		t.Fatalf("program too short: %d", len(prog))
	}
	if prog[0].Code != bpfLD|bpfW|bpfABS || prog[0].K != seccompDataOffsetArch {
		t.Errorf("insn[0] must be LD [arch]: %+v", prog[0])
	}
	if prog[1].Code != bpfJMP|bpfJEQ|bpfK || prog[1].Jt != 1 {
		t.Errorf("insn[1] must be JEQ arch, Jt=1: %+v", prog[1])
	}
	if prog[2].Code != bpfRET|bpfK || prog[2].K != seccompRetKill {
		t.Errorf("insn[2] must be RET KILL: %+v", prog[2])
	}
}

func TestCombinedFilter_Verdicts(t *testing.T) {
	arch, nums, err := archFor(runtime.GOARCH)
	if err != nil {
		t.Skipf("arch %s not supported by the seccomp compiler", runtime.GOARCH)
	}
	retErrno := seccompRetErrno | uint32(unix.EPERM)

	const (
		oRdonly    uint32 = 0x0000
		oWronly    uint32 = 0x0001
		cloneThr   uint32 = 0x00010000 // CLONE_THREAD — not a namespace flag
		cloneNewUs uint32 = 0x10000000 // CLONE_NEWUSER — in cloneNewMask
		afInet     uint32 = 2
		afPacket   uint32 = 17
		benignNR   uint32 = 0xFFFE // not a real syscall: no denylist / arg rule
	)
	zero := [6]uint32{}
	withArg := func(idx int, v uint32) [6]uint32 {
		a := [6]uint32{}
		a[idx] = v
		return a
	}

	harvest, err := CompileFilterWithArgs(ProfileHarvest, argRulesFor(ProfileHarvest, nums))
	if err != nil {
		t.Fatalf("Harvest compile: %v", err)
	}
	dial, err := CompileFilterWithArgs(ProfileDial, argRulesFor(ProfileDial, nums))
	if err != nil {
		t.Fatalf("Dial compile: %v", err)
	}
	exploit, err := CompileFilterWithArgs(ProfileExploit, argRulesFor(ProfileExploit, nums))
	if err != nil {
		t.Fatalf("Exploit compile: %v", err)
	}

	cases := []struct {
		name string
		prog []unix.SockFilter
		arch uint32
		nr   uint32
		args [6]uint32
		want uint32
	}{
		// Denylist must be REACHABLE (the bug made these ALLOW).
		{"harvest execve denied", harvest, arch, nums.Execve, zero, retErrno},
		{"harvest ptrace denied", harvest, arch, nums.Ptrace, zero, retErrno},
		{"harvest bpf denied", harvest, arch, nums.Bpf, zero, retErrno},
		{"exploit execve denied", exploit, arch, nums.Execve, zero, retErrno},
		{"exploit ptrace denied", exploit, arch, nums.Ptrace, zero, retErrno},
		// Arg rules must DENY on the bad value, ALLOW on the good one.
		{"harvest openat O_WRONLY denied", harvest, arch, nums.Openat, withArg(2, oWronly), retErrno},
		{"harvest openat O_RDONLY allowed", harvest, arch, nums.Openat, withArg(2, oRdonly), seccompRetAllow},
		{"harvest clone NEWUSER denied", harvest, arch, nums.Clone, withArg(0, cloneNewUs), retErrno},
		{"harvest clone THREAD allowed", harvest, arch, nums.Clone, withArg(0, cloneThr), seccompRetAllow},
		{"exploit clone NEWUSER denied", exploit, arch, nums.Clone, withArg(0, cloneNewUs), retErrno},
		{"dial socket AF_PACKET denied", dial, arch, nums.Socket, withArg(0, afPacket), retErrno},
		{"dial socket AF_INET allowed", dial, arch, nums.Socket, withArg(0, afInet), seccompRetAllow},
		// A syscall that is neither blocked nor gated is allowed.
		{"harvest benign allowed", harvest, arch, benignNR, zero, seccompRetAllow},
		// Wrong architecture is killed before anything else runs.
		{"harvest wrong arch killed", harvest, arch + 1, nums.Execve, zero, seccompRetKill},
	}
	for _, c := range cases {
		got := evalSeccomp(t, c.prog, c.arch, c.nr, c.args)
		if got != c.want {
			t.Errorf("%s: verdict 0x%x, want 0x%x", c.name, got, c.want)
		}
	}
}

func TestRuleBodyLen_Matches_CombinedEmit(t *testing.T) {
	// ruleBodyLen must equal what emitCombinedRuleBody emits, otherwise
	// the section length (and every jump computed from it) is wrong.
	mask := NewArgDenyMaskAny(257, 2, 0x0001)
	if got, emit := ruleBodyLen(mask), len(emitCombinedRuleBody(mask, 0, 100)); got != emit {
		t.Errorf("mask rule: predict %d vs emit %d", got, emit)
	}
	eq := NewArgDenyEqual(41, 0, 17, 16, 4)
	if got, emit := ruleBodyLen(eq), len(emitCombinedRuleBody(eq, 0, 100)); got != emit {
		t.Errorf("equal rule: predict %d vs emit %d", got, emit)
	}
}
