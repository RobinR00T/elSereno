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
//
// v2.61+: iterates Profiles() instead of a hand-listed
// slice. v2.32 added ProfileScan but this test (and its
// sibling distinct-schemes test) kept the v1.50 hard-coded
// 3-element list and silently skipped ProfileScan for 9
// cycles — that's exactly the regression Profiles() is
// designed to eliminate.
func TestDarwinProfileSchemesPresent(t *testing.T) {
	for _, p := range Profiles() {
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
// that we didn't copy-paste exploit.sb to harvest/dial/scan.
// A regression where every profile had the same scheme
// would silently neuter the per-profile guarantees.
//
// v2.61+: iterates pairs from Profiles() rather than a
// hand-coded matrix; ProfileScan is now covered.
func TestDarwinAllProfilesHaveDistinctSchemes(t *testing.T) {
	all := Profiles()
	for i := 0; i < len(all); i++ {
		for j := i + 1; j < len(all); j++ {
			a, b := all[i], all[j]
			if macSandboxProfileSCM[a] == macSandboxProfileSCM[b] {
				t.Errorf("profiles %q and %q have identical .sb schemes", a, b)
			}
		}
	}

	// Per-profile distinguishing signal:
	//   exploit  → must allow network*       (full inet)
	//   harvest  → must allow network-outbound (DNS + restricted)
	//   dial     → must deny network*        (no inet at all)
	//   scan     → must allow network*       + deny file-write*
	exploit := macSandboxProfileSCM[ProfileExploit]
	harvest := macSandboxProfileSCM[ProfileHarvest]
	dial := macSandboxProfileSCM[ProfileDial]
	scan := macSandboxProfileSCM[ProfileScan]

	if !strings.Contains(exploit, "(allow network*)") {
		t.Errorf("exploit profile missing (allow network*)")
	}
	if !strings.Contains(harvest, "(allow network-outbound") {
		t.Errorf("harvest profile missing (allow network-outbound)")
	}
	if !strings.Contains(dial, "(deny network*)") {
		t.Errorf("dial profile missing (deny network*)")
	}
	// v2.61+: scan profile shape — network probes ON, but
	// no file writes (scanner shouldn't touch disk; parent
	// serialises findings via the audit chain).
	if !strings.Contains(scan, "(allow network*)") {
		t.Errorf("scan profile missing (allow network*)")
	}
	if !strings.Contains(scan, "(deny file-write*)") {
		t.Errorf("scan profile missing (deny file-write*)")
	}
}

// TestDarwinSchemeFor (v2.61+) — SchemeFor returns the live
// scheme for every recognised profile and ("", false) for
// unknown values. This is the introspection accessor that
// the `sandbox introspect` verb (vNext) and audit-tooling
// will source from; the unit test fences the API shape so
// downstream callers don't regress.
func TestDarwinSchemeFor(t *testing.T) {
	for _, p := range Profiles() {
		scm, ok := SchemeFor(p)
		if !ok {
			t.Errorf("SchemeFor(%q) returned ok=false", p)
			continue
		}
		if scm == "" {
			t.Errorf("SchemeFor(%q) returned empty scheme", p)
		}
		// Cross-check: same string the cgo Load() path will
		// hand to sandbox_init.
		if scm != macSandboxProfileSCM[p] {
			t.Errorf("SchemeFor(%q) returned a different string than the live map", p)
		}
	}
	if scm, ok := SchemeFor(Profile("bogus")); ok || scm != "" {
		t.Errorf("SchemeFor(bogus) = (%q, %v); want (\"\", false)", scm, ok)
	}
}
