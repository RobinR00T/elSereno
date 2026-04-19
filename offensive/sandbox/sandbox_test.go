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

func TestLoad_ValidProfileSucceeds(t *testing.T) {
	// On Linux: PR_SET_NO_NEW_PRIVS installs; Availability.Available=true.
	// On macOS: degraded; Available=false. Both are acceptable.
	res, err := Load(ProfileHarvest)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if res.Profile != ProfileHarvest {
		t.Fatalf("profile = %q, want %q", res.Profile, ProfileHarvest)
	}
	if res.Availability.Kind == "" {
		t.Fatal("empty Kind")
	}
}
