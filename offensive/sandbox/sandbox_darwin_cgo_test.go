//go:build offensive && darwin && cgo

package sandbox

import (
	"strings"
	"testing"
)

// TestDarwinProfileSchemesPresent — every defined Profile
// must map to a non-empty .sb Scheme string. A missing
// entry would silently yield Availability.Available=false
// at runtime; this test catches it at build time.
func TestDarwinProfileSchemesPresent(t *testing.T) {
	for _, p := range []Profile{ProfileExploit, ProfileHarvest, ProfileDial} {
		scm, ok := macSandboxProfileSCM[p]
		if !ok {
			t.Errorf("profile %q has no .sb scheme", p)
			continue
		}
		if !strings.Contains(scm, "(version 1)") {
			t.Errorf("profile %q scheme missing (version 1) header:\n%s", p, scm)
		}
		if !strings.Contains(scm, "deny default") {
			t.Errorf("profile %q scheme missing 'deny default' baseline:\n%s", p, scm)
		}
	}
}

// TestDarwinLoadInvalidProfile — Load with an unknown
// profile errors at the input check before touching
// sandbox_init.
func TestDarwinLoadInvalidProfile(t *testing.T) {
	_, err := Load(Profile("bogus"))
	if err == nil {
		t.Fatalf("expected error on unknown profile")
	}
	if !strings.Contains(err.Error(), "unknown profile") {
		t.Errorf("error = %v, want 'unknown profile'", err)
	}
}

// TestDarwinAllProfilesHaveDistinctSchemes — sanity-check
// that we didn't copy-paste exploit.sb to harvest/dial. A
// regression where every profile had the same scheme
// would silently neuter the per-profile guarantees.
func TestDarwinAllProfilesHaveDistinctSchemes(t *testing.T) {
	exploit := macSandboxProfileSCM[ProfileExploit]
	harvest := macSandboxProfileSCM[ProfileHarvest]
	dial := macSandboxProfileSCM[ProfileDial]

	if exploit == harvest {
		t.Errorf("exploit + harvest schemes are identical")
	}
	if exploit == dial {
		t.Errorf("exploit + dial schemes are identical")
	}
	if harvest == dial {
		t.Errorf("harvest + dial schemes are identical")
	}

	// Per-profile distinguishing signal:
	//   exploit  → must allow network*       (full inet)
	//   harvest  → must allow network-outbound (DNS + restricted)
	//   dial     → must deny network*        (no inet at all)
	if !strings.Contains(exploit, "(allow network*)") {
		t.Errorf("exploit profile missing (allow network*)")
	}
	if !strings.Contains(harvest, "(allow network-outbound") {
		t.Errorf("harvest profile missing (allow network-outbound)")
	}
	if !strings.Contains(dial, "(deny network*)") {
		t.Errorf("dial profile missing (deny network*)")
	}
}
