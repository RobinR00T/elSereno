//go:build offensive && linux

package sandbox

import "testing"

// The no-write profiles (Harvest, Scan) must close the file-open
// escape: deny openat2 + creat outright (openat2 is unfilterable, creat
// always writes) and arg-filter open on write flags (open's flags are
// arg 1, unlike openat's arg 2).
func TestOpenHardening(t *testing.T) {
	for _, p := range []Profile{ProfileHarvest, ProfileScan} {
		blocked := blockedSyscalls(p, syscallsAMD64)
		if !containsSyscall(blocked, syscallsAMD64.Openat2) {
			t.Errorf("%v: openat2 not in denylist", p)
		}
		if !containsSyscall(blocked, syscallsAMD64.Creat) {
			t.Errorf("%v: creat not in denylist", p)
		}
		if !hasOpenWriteRule(argRulesFor(p, syscallsAMD64), syscallsAMD64.Open) {
			t.Errorf("%v: no open write-flag arg-filter rule", p)
		}
	}
}

func containsSyscall(s []uint32, v uint32) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func hasOpenWriteRule(rules []ArgDenyRule, openNr uint32) bool {
	for _, r := range rules {
		if r.Syscall == openNr && r.ArgIndex == 1 && r.MaskBits != 0 {
			return true
		}
	}
	return false
}
