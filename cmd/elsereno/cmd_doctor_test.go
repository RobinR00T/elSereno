package main

import (
	"strings"
	"testing"
)

// TestCheckNmap_MissingIsSkip: elsereno never runs nmap, so a missing
// nmap is a skip and the message must not claim scan needs it (until
// 2026-10-18 it said "scan requires nmap >= 7.80").
func TestCheckNmap_MissingIsSkip(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	r := checkNmap()
	if r.status != doctorSkip {
		t.Fatalf("status = %q, want skip", r.status)
	}
	if strings.Contains(r.message, "requires") {
		t.Fatalf("message still claims nmap is required: %q", r.message)
	}
}

// TestRunDoctor_SixChecksNoFailOnSkip: doctor runs exactly the six
// checks the docs list, and on a machine without nmap or root none of
// them fails.
func TestRunDoctor_SixChecksNoFailOnSkip(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	results := runDoctor()
	var names []string
	for _, r := range results {
		names = append(names, r.name)
		if r.name == "privileged scan" || r.name == "nmap" {
			if r.status == doctorFail || r.status == doctorWarn {
				t.Errorf("%s: status %q, want ok or skip (%s)", r.name, r.status, r.message)
			}
		}
	}
	want := "go runtime,platform,privileged scan,nmap,ipv6,disk"
	if got := strings.Join(names, ","); got != want {
		t.Fatalf("checks = %s, want %s", got, want)
	}
}
