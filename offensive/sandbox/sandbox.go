//go:build offensive

package sandbox

// Profile names the operational profiles declared in ADR-042.
// v2.32+ adds ProfileScan for read-only scan subprocesses.
type Profile string

// Profile values.
const (
	// ProfileExploit — for CVE exploit subprocesses. Network allowed,
	// file writes heavily restricted.
	ProfileExploit Profile = "exploit"
	// ProfileHarvest — for credential-harvest helpers. DNS allowed,
	// file writes denied.
	ProfileHarvest Profile = "harvest"
	// ProfileDial — for dial subprocesses. TTY ioctls allowed,
	// network socket calls denied.
	ProfileDial Profile = "dial"
	// ProfileScan (v2.32+) — for read-only scan subprocesses
	// (default-build scanners). Network read+write allowed for
	// probing; file writes blocked entirely; process-exec
	// blocked so a compromised target can't pivot. Defence
	// in depth — the default scan path is already "safe" but
	// dropping unused capabilities tightens the blast radius.
	ProfileScan Profile = "scan"
)

// Profiles (v2.61+) returns the canonical list of recognised
// profile values in declaration order. Tests and operator
// tooling that need to iterate every profile should source from
// here rather than hand-listing — historically v2.32 added
// ProfileScan but the v1.50 darwin tests kept iterating the
// original 3-element slice and silently missed it for 9 cycles.
// Single source of truth: this function. Valid() delegates here
// so the two stay in sync by construction.
func Profiles() []Profile {
	return []Profile{ProfileExploit, ProfileHarvest, ProfileDial, ProfileScan}
}

// Valid reports whether p is a recognised profile.
func (p Profile) Valid() bool {
	for _, known := range Profiles() {
		if p == known {
			return true
		}
	}
	return false
}

// Availability reports whether this platform can load a sandbox
// profile. On Linux, Load() installs prctl(PR_SET_NO_NEW_PRIVS) and
// (in F6) a seccomp-BPF filter. On every other platform, Load()
// returns a degraded result with Available=false; offensive
// subprocess execution continues but the audit entry records
// `sandbox=unavailable` so operators know to treat the result as
// "best effort".
type Availability struct {
	Available bool
	Kind      string // "seccomp-bpf" | "unavailable"
	Reason    string // free-text detail
}

// LoadResult is returned by Load. It exists so callers can record
// the outcome in the audit event alongside the offensive_allowed
// entry.
type LoadResult struct {
	Profile      Profile
	Availability Availability
}
