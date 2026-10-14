//go:build offensive

package main

import "testing"

// TestBuildDNP3Allowlist_PrimaryFunctions: --dnp3-primary accepts only
// the user-data link functions 3 and 4. 0, 2 and 9 always pass, any
// other is discarded as an invalid frame (PITF-081), and a list without
// 3 or 4 would refuse every user-data frame, Read included.
func TestBuildDNP3Allowlist_PrimaryFunctions(t *testing.T) {
	t.Parallel()
	for _, ok := range []string{"3", "0x04"} {
		if _, err := buildDNP3Allowlist(nil, nil, nil, nil, []string{ok}); err != nil {
			t.Errorf("--dnp3-primary %s rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"0", "1", "2", "5", "9", "10", "15", "255"} {
		if _, err := buildDNP3Allowlist(nil, nil, nil, nil, []string{bad}); err == nil {
			t.Errorf("--dnp3-primary %s accepted", bad)
		}
	}
}
