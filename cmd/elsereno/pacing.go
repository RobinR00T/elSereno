package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"local/elsereno/internal/config"
	"local/elsereno/internal/core"
	"local/elsereno/internal/scanner"
)

// pacingFlags are the pace controls shared by the commands that probe
// many targets (scan, discover): a named profile plus two per-host
// overrides. Each command keeps its own global caps (scan --rate,
// --max-concurrent, --retries; discover --parallel), which also
// override the profile when given.
type pacingFlags struct {
	profile         string
	interProbeDelay time.Duration
	maxPerHost      int
}

func addPacingFlags(cmd *cobra.Command, p *pacingFlags) {
	cmd.Flags().StringVar(&p.profile, "profile", scanner.DefaultProfile,
		"pacing profile: "+strings.Join(scanner.ProfileNames(), " | ")+"; explicit flags override it (the command's long help lists what each one sets)")
	cmd.Flags().DurationVar(&p.interProbeDelay, "inter-probe-delay", 0,
		"minimum gap between the start of two probes against the same host (overrides the profile; 0 turns the pause off)")
	cmd.Flags().IntVar(&p.maxPerHost, "max-conns-per-host", 0,
		"probes in flight against one host (overrides the profile and scanner.max_concurrent_per_host; 0 = the profile's)")
}

// pacing is the pace a command runs with, after profile, config and
// explicit flags are combined (explicit flag > profile > config).
type pacing struct {
	profile       string
	maxConcurrent int
	maxPerHost    int
	interval      time.Duration
	ratePerSec    int
	retries       int
}

// pacingOverrides carries the command's own global flags and whether
// the operator set them.
type pacingOverrides struct {
	maxConcurrent    int
	maxConcurrentSet bool
	ratePerSec       int
	rateSet          bool
	retries          int
	retriesSet       bool
}

func resolvePacing(cmd *cobra.Command, pf pacingFlags, cfg config.ScannerConfig, o pacingOverrides) (pacing, error) {
	name := pf.profile
	if name == "" { // callers that build the flags by hand (tests)
		name = scanner.DefaultProfile
	}
	prof, err := scanner.LookupProfile(name)
	if err != nil {
		return pacing{}, fail(core.ExitUsage, err)
	}
	if pf.maxPerHost < 0 || pf.interProbeDelay < 0 {
		return pacing{}, fail(core.ExitUsage, fmt.Errorf("--max-conns-per-host and --inter-probe-delay cannot be negative"))
	}
	p := pacing{
		profile:       prof.Name,
		maxConcurrent: pickPositive(prof.MaxConcurrentTargets, cfg.MaxConcurrentTargets),
		maxPerHost:    pickPositive(prof.MaxPerHost, cfg.MaxConcurrentPerHost),
		interval:      prof.MinHostInterval,
		ratePerSec:    prof.RatePerSecond,
		retries:       prof.MaxRetries,
	}
	if o.maxConcurrentSet && o.maxConcurrent > 0 {
		p.maxConcurrent = o.maxConcurrent
	}
	if o.rateSet {
		p.ratePerSec = o.ratePerSec
	}
	if o.retriesSet {
		p.retries = o.retries
	}
	if cmd.Flags().Changed("max-conns-per-host") && pf.maxPerHost > 0 {
		p.maxPerHost = pf.maxPerHost
	}
	if cmd.Flags().Changed("inter-probe-delay") {
		p.interval = pf.interProbeDelay
	}
	if p.maxPerHost < 1 {
		p.maxPerHost = 1
	}
	return p, nil
}

// String is the line printed to stderr when a run starts, so the
// operator sees the pace actually applied.
func (p pacing) String() string {
	rate := "no overall rate cap"
	if p.ratePerSec > 0 {
		rate = fmt.Sprintf("%d probes/s overall", p.ratePerSec)
	}
	gap := "no pause between probes to a host"
	if p.interval > 0 {
		gap = p.interval.String() + " between probes to a host"
	}
	retries := fmt.Sprintf("%d retries", p.retries)
	if p.retries == 1 {
		retries = "1 retry"
	}
	return fmt.Sprintf("pacing %s: %d in flight, %d per host, %s, %s, %s",
		p.profile, p.maxConcurrent, p.maxPerHost, gap, rate, retries)
}

// profilesHelp renders the profile table for a command's long help.
func profilesHelp() string {
	var b strings.Builder
	b.WriteString("Pacing profiles (--profile; explicit flags override them):\n")
	for _, p := range scanner.Profiles() {
		fmt.Fprintf(&b, "  %-10s %s\n", p.Name, p.Summary)
	}
	b.WriteString("The numbers are conservative starting points, not values validated\n" +
		"against any vendor's device: measure before trusting them on a device\n" +
		"known to be delicate.")
	return b.String()
}
