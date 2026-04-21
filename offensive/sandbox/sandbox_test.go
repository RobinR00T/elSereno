//go:build offensive

package sandbox

import "testing"

func TestProfileValid(t *testing.T) {
	for _, p := range []Profile{ProfileExploit, ProfileHarvest, ProfileDial} {
		if !p.Valid() {
			t.Errorf("%q should be valid", p)
		}
	}
	if Profile("bogus").Valid() {
		t.Error("bogus should not be valid")
	}
}

func TestLoad_BadProfileRejected(t *testing.T) {
	_, err := Load(Profile("nope"))
	if err == nil {
		t.Fatal("expected error on unknown profile")
	}
}

// TestLoad_ValidProfileOnNonLinux exercises the degraded path
// (no seccomp, Availability.Available=false). On Linux, Load
// actually installs the kernel filter and is exercised by the
// sandbox_integration build — see sandbox_integration_test.go.
// This test stays here so macOS dev machines keep the profile
// validation path green.
func TestLoad_ValidProfileOnNonLinux(t *testing.T) {
	if isLinux() {
		t.Skip("integration build covers Linux; see sandbox_integration_test.go")
	}
	res, err := Load(ProfileHarvest)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if res.Profile != ProfileHarvest {
		t.Fatalf("profile = %q, want %q", res.Profile, ProfileHarvest)
	}
	if res.Availability.Available {
		t.Fatalf("non-Linux must report Available=false, got %+v", res.Availability)
	}
	if res.Availability.Kind != "unavailable" {
		t.Fatalf("non-Linux must report Kind=unavailable, got %q", res.Availability.Kind)
	}
}
