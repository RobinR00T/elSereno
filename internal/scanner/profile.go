package scanner

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// ErrUnknownProfile is returned by LookupProfile for a name that is not
// one of Profiles().
var ErrUnknownProfile = errors.New("scanner: unknown pacing profile")

// Profile is a named pacing preset for active probing. A zero
// MaxConcurrentTargets or MaxPerHost keeps the config value
// (scanner.max_concurrent_targets, scanner.max_concurrent_per_host). There is no per-probe
// timeout: each plugin sets its own I/O deadline and does not take the
// context's, so a timeout here would not shorten a read.
//
// The numbers are conservative starting points chosen for this tool,
// not values validated against any vendor's device: an operator who
// knows a device is delicate should still measure, and override with
// the individual flags.
type Profile struct {
	// Name is the profile's CLI name.
	Name string
	// Summary is the one-line description shown in help and docs.
	Summary string
	// MaxConcurrentTargets caps probes in flight across all hosts.
	MaxConcurrentTargets int
	// MaxPerHost caps probes in flight against one host.
	MaxPerHost int
	// MinHostInterval is the minimum gap between probe starts on one host.
	MinHostInterval time.Duration
	// RatePerSecond caps probe starts per second across all hosts (0 = none).
	RatePerSecond int
	// MaxRetries bounds retries on a timeout.
	MaxRetries int
}

// DefaultProfile is the profile a command uses without --profile. It
// reproduces the pace scan had before profiles existed (config caps,
// two retries, no pause).
const DefaultProfile = "normal"

var profiles = map[string]Profile{
	"aggressive": {
		Name:                 "aggressive",
		Summary:              "lab or IT ranges only: 256 in flight, 4 per host, no pause, 2 retries",
		MaxConcurrentTargets: 256,
		MaxPerHost:           4,
		MaxRetries:           2,
	},
	"normal": {
		Name:       "normal",
		Summary:    "default: config caps (100 in flight, 1 per host), no pause, 2 retries",
		MaxRetries: 2,
	},
	"safe": {
		Name:                 "safe",
		Summary:              "production OT: 16 in flight, 1 per host, 1s between probes to a host, 10 probes/s overall, 1 retry",
		MaxConcurrentTargets: 16,
		MaxPerHost:           1,
		MinHostInterval:      time.Second,
		RatePerSecond:        10,
		MaxRetries:           1,
	},
	"fragile": {
		Name:                 "fragile",
		Summary:              "devices known to hang on probes: 4 in flight, 1 per host, 10s between probes to a host, 2 probes/s overall, no retry",
		MaxConcurrentTargets: 4,
		MaxPerHost:           1,
		MinHostInterval:      10 * time.Second,
		RatePerSecond:        2,
		MaxRetries:           0,
	},
}

// LookupProfile returns the named profile. The match is case-insensitive.
func LookupProfile(name string) (Profile, error) {
	p, ok := profiles[strings.ToLower(strings.TrimSpace(name))]
	if !ok {
		return Profile{}, fmt.Errorf("%w %q (valid: %s)", ErrUnknownProfile, name, strings.Join(ProfileNames(), ", "))
	}
	return p, nil
}

// ProfileNames lists the profile names, from fastest to gentlest.
func ProfileNames() []string {
	names := make([]string, 0, len(profiles))
	for n := range profiles {
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool {
		return gentleness(profiles[names[i]]) < gentleness(profiles[names[j]])
	})
	return names
}

// Profiles returns every profile, from fastest to gentlest.
func Profiles() []Profile {
	names := ProfileNames()
	out := make([]Profile, 0, len(names))
	for _, n := range names {
		out = append(out, profiles[n])
	}
	return out
}

// gentleness orders profiles by the pause they impose on a host, then by
// how few probes they keep in flight.
func gentleness(p Profile) int64 {
	inflight := p.MaxConcurrentTargets
	if inflight == 0 {
		inflight = 100
	}
	return int64(p.MinHostInterval/time.Millisecond)*1000 + int64(1000-inflight)
}
