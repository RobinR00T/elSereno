//go:build offensive && linux

package sandbox

import (
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

func TestArgFilterPresets_Amd64Tables(t *testing.T) {
	// On amd64 the syscall numbers are openat=257 + socket=41.
	rules := ArgFilterPresets(syscallsAMD64)
	if len(rules) != 2 {
		t.Fatalf("expected 2 preset rules (openat + socket), got %d", len(rules))
	}
	var sawOpenat, sawSocket bool
	for _, r := range rules {
		if r.Syscall == 257 { // openat
			sawOpenat = true
			if r.MaskBits == 0 {
				t.Errorf("openat preset should be mask-mode")
			}
			// Mask should include O_WRONLY (1) and O_RDWR (2).
			if r.MaskBits&0x0003 == 0 {
				t.Errorf("openat mask 0x%x missing O_WRONLY|O_RDWR", r.MaskBits)
			}
		}
		if r.Syscall == 41 { // socket
			sawSocket = true
			if len(r.EqualValues) == 0 {
				t.Errorf("socket preset should be equal-mode")
			}
			// AF_PACKET = 17 + AF_NETLINK = 16.
			gotPacket, gotNetlink := false, false
			for _, v := range r.EqualValues {
				switch v {
				case 17:
					gotPacket = true
				case 16:
					gotNetlink = true
				}
			}
			if !gotPacket {
				t.Errorf("socket preset missing AF_PACKET (17): %v", r.EqualValues)
			}
			if !gotNetlink {
				t.Errorf("socket preset missing AF_NETLINK (16): %v", r.EqualValues)
			}
		}
	}
	if !sawOpenat {
		t.Error("preset list missing openat rule")
	}
	if !sawSocket {
		t.Error("preset list missing socket rule")
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

func TestCompileArgFilter_EmptyRulesReturnsNil(t *testing.T) {
	if got := CompileArgFilter(nil); got != nil {
		t.Errorf("nil rules: got %v, want nil", got)
	}
	if got := CompileArgFilter([]ArgDenyRule{}); got != nil {
		t.Errorf("empty rules: got %v, want nil", got)
	}
}

func TestCompileArgFilter_MaskRule_InsnLayout(t *testing.T) {
	// One mask rule should compile to:
	//   LD nr / JEQ syscall / LD arg / AND mask / JEQ 0 /
	//   RET ALLOW / RET ERRNO|EPERM
	// = 7 instructions.
	r := NewArgDenyMaskAny(257, 2, 0x0001) // openat O_WRONLY
	prog := CompileArgFilter([]ArgDenyRule{r})
	if len(prog) != 7 {
		t.Fatalf("len(prog) = %d, want 7", len(prog))
	}
	// First insn: LD nr (offset 0).
	if prog[0].K != seccompDataOffsetNR {
		t.Errorf("insn[0] K = %d, want %d (NR offset)", prog[0].K, seccompDataOffsetNR)
	}
	// Second insn: JEQ syscall.
	if prog[1].K != 257 {
		t.Errorf("insn[1] K = %d, want 257 (openat)", prog[1].K)
	}
	// Tail: RET ALLOW + RET ERRNO|EPERM.
	if prog[5].K != seccompRetAllow {
		t.Errorf("insn[5] K = 0x%x, want SECCOMP_RET_ALLOW (0x%x)", prog[5].K, seccompRetAllow)
	}
	if prog[6].K != seccompRetErrno|uint32(unix.EPERM) {
		t.Errorf("insn[6] K = 0x%x, want SECCOMP_RET_ERRNO|EPERM (0x%x)", prog[6].K, seccompRetErrno|uint32(unix.EPERM))
	}
}

func TestCompileArgFilter_EqualRule_InsnLayout(t *testing.T) {
	// One equal rule with 2 values:
	//   LD nr / JEQ syscall / LD arg / JEQ value0 / JEQ value1 /
	//   RET ALLOW / RET ERRNO|EPERM
	// = 7 instructions.
	r := NewArgDenyEqual(41, 0, 17, 16) // socket AF_PACKET / AF_NETLINK
	prog := CompileArgFilter([]ArgDenyRule{r})
	if len(prog) != 7 {
		t.Fatalf("len(prog) = %d, want 7 (got %d)", len(prog), len(prog))
	}
	if prog[1].K != 41 {
		t.Errorf("insn[1] K = %d, want 41 (socket)", prog[1].K)
	}
	if prog[3].K != 17 {
		t.Errorf("insn[3] K = %d, want 17 (AF_PACKET)", prog[3].K)
	}
	if prog[4].K != 16 {
		t.Errorf("insn[4] K = %d, want 16 (AF_NETLINK)", prog[4].K)
	}
}

func TestCompileFilterWithArgs_AppendsArgPrologue(t *testing.T) {
	syscallOnly, err := FilterProgram(ProfileHarvest)
	if err != nil {
		t.Fatalf("FilterProgram: %v", err)
	}
	combined, err := CompileFilterWithArgs(ProfileHarvest, ArgFilterPresets(syscallsAMD64))
	if err != nil {
		t.Fatalf("CompileFilterWithArgs: %v", err)
	}
	if len(combined) <= len(syscallOnly) {
		t.Fatalf("combined len %d should exceed syscall-only %d", len(combined), len(syscallOnly))
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
		t.Errorf("nil rules should yield same length: got %d vs %d", len(noArgs), len(syscallOnly))
	}
}

func TestCompileFilterWithArgs_RejectsBadProfile(t *testing.T) {
	_, err := CompileFilterWithArgs(Profile("bogus"), nil)
	if err == nil {
		t.Fatal("expected error for unknown profile")
	}
}

func TestRuleBodyLen_Matches_Emitted(t *testing.T) {
	// The Pass-1 length predictor must equal the actual emit
	// count, otherwise jump offsets are wrong.
	mask := NewArgDenyMaskAny(257, 2, 0x0001)
	if got := ruleBodyLen(mask); got != len(emitRuleBody(mask, 5)) {
		t.Errorf("mask rule: predict %d vs emit %d", got, len(emitRuleBody(mask, 5)))
	}
	eq := NewArgDenyEqual(41, 0, 17, 16, 4)
	if got := ruleBodyLen(eq); got != len(emitRuleBody(eq, 5)) {
		t.Errorf("equal rule: predict %d vs emit %d", got, len(emitRuleBody(eq, 5)))
	}
}
