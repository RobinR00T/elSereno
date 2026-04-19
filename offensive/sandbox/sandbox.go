//go:build offensive

package sandbox

// Profile names the three operational profiles declared in ADR-042.
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
)

// Valid reports whether p is a recognised profile.
func (p Profile) Valid() bool {
	switch p {
	case ProfileExploit, ProfileHarvest, ProfileDial:
		return true
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
