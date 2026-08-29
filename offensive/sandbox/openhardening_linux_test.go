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

// clone must be arg-filtered to deny CLONE_NEW* namespace creation on
// every profile, while staying OUT of the syscall denylist (the Go
// runtime needs clone for thread creation).
func TestCloneNamespaceFilter(t *testing.T) {
	for _, p := range []Profile{ProfileHarvest, ProfileDial, ProfileScan, ProfileExploit} {
		found := false
		for _, r := range argRulesFor(p, syscallsAMD64) {
			if r.Syscall == syscallsAMD64.Clone && r.ArgIndex == 0 && r.MaskBits == cloneNewMask {
				found = true
			}
		}
		if !found {
			t.Errorf("%v: no clone CLONE_NEW* arg-filter rule", p)
		}
	}
	if containsSyscall(blockedSyscalls(ProfileExploit, syscallsAMD64), syscallsAMD64.Clone) {
		t.Error("clone in the denylist would kill the Go runtime")
	}
}
