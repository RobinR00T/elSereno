package main

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"

	"local/elsereno/internal/core"
	"local/elsereno/internal/scanner"
	"local/elsereno/internal/scanorch"
)

// defaultScanRunner is the cmd-side scanorch.JobRunner that
// turns a queued Job into actual scanner.Run output. It owns the
// imports the orchestration shell deliberately doesn't carry
// (input parsing + plugin-registry lookup + scanner dispatch).
//
// Single-plugin contract for v1.61: each job names exactly one
// plugin in Plugins. Multi-plugin parallel dispatch (one job
// fans out to N plugins per target) is a future cycle. Forcing
// one-plugin-per-job keeps the Stats accounting unambiguous —
// FindingsCount is "how many findings did THIS plugin produce
// against THESE targets", not a sum across heterogeneous probes.
type defaultScanRunner struct {
	// concurrency caps the scanner's MaxConcurrentTargets per
	// job. Zero → 100 (the scanner package default). Higher
	// concurrency burns more sockets per scan; lower flattens
	// the burst.
	concurrency int
}

// Sentinel errors so callers can distinguish runner-failure
// classes.
var (
	// ErrRunnerNoPlugin means the Job's Plugins slice was empty.
	// v1.61 requires exactly one plugin per job.
	ErrRunnerNoPlugin = errors.New("scan runner: job must specify exactly one plugin in Plugins (multi-plugin not yet supported)")
	// ErrRunnerTooManyPlugins means the Job named more than one
	// plugin; multi-plugin dispatch lands in a future cycle.
	ErrRunnerTooManyPlugins = errors.New("scan runner: job specified multiple plugins (multi-plugin not yet supported)")
	// ErrRunnerUnknownPlugin means the named plugin isn't in
	// the registry (typo / build-tag mismatch).
	ErrRunnerUnknownPlugin = errors.New("scan runner: plugin not found in registry")
)

// Run implements scanorch.JobRunner. Steps:
//
//  1. Validate exactly one plugin name.
//  2. Look up the plugin via core.RegisteredPlugins.
//  3. Parse Job.Input via the existing inputParseOpts dispatcher.
//  4. Run scanner.Run with the plugin's Probe.
//  5. Drain findings + errs channels, accumulating Stats.
func (r *defaultScanRunner) Run(ctx context.Context, job scanorch.Job) (scanorch.Stats, error) {
	if len(job.Plugins) == 0 {
		return scanorch.Stats{}, ErrRunnerNoPlugin
	}
	if len(job.Plugins) > 1 {
		return scanorch.Stats{}, ErrRunnerTooManyPlugins
	}
	plugin, ok := lookupPluginByName(job.Plugins[0])
	if !ok {
		return scanorch.Stats{}, fmt.Errorf("%w: %s", ErrRunnerUnknownPlugin, job.Plugins[0])
	}
	targets, err := parseInput(ctx, inputParseOpts{
		InputKind:   job.Input,
		DefaultPort: job.DefaultPort,
	})
	if err != nil {
		return scanorch.Stats{}, fmt.Errorf("scan runner: parse input: %w", err)
	}
	stats := scanorch.Stats{TargetsSeen: len(targets)}
	if len(targets) == 0 {
		return stats, nil
	}
	concurrency := r.concurrency
	if concurrency <= 0 {
		concurrency = 100
	}
	scn := scanner.New(scanner.Options{MaxConcurrentTargets: concurrency})
	probe := plugin.Factory().Probe
	findings, errs := scn.Run(ctx, targets, probe)
	stats = drainScanRun(findings, errs, stats)
	return stats, nil
}

// drainScanRun consumes the scanner's findings + errs channels
// to completion, accumulating Stats. Errors from the scanner
// are best-effort: scanner.Run emits transient probe failures
// on errs (one per target that failed); we count them as
// scanned-but-no-finding rather than aborting the whole job.
// A truly fatal error (ErrNoTargets / ctx cancellation) is
// already surfaced by scanner.Run's own short-circuit.
func drainScanRun(findings <-chan core.Finding, errs <-chan error, stats scanorch.Stats) scanorch.Stats {
	var (
		findingsCount  atomic.Int64
		targetsScanned atomic.Int64
	)
	for findings != nil || errs != nil {
		select {
		case _, ok := <-findings:
			if !ok {
				findings = nil
				continue
			}
			findingsCount.Add(1)
			targetsScanned.Add(1)
		case _, ok := <-errs:
			if !ok {
				errs = nil
				continue
			}
			// Probe error → count the target as scanned (we tried)
			// but don't bump findingsCount.
			targetsScanned.Add(1)
		}
	}
	stats.FindingsCount = int(findingsCount.Load())
	stats.TargetsScanned = int(targetsScanned.Load())
	return stats
}

// lookupPluginByName walks the registry. Plugin lookup by name
// is also done in cmd_fingerprint.go; this helper is local to
// the scan-runner because we want a (Plugin, ok) shape rather
// than the (Plugin, error) shape of cmd_fingerprint.go's
// helper.
func lookupPluginByName(name string) (core.Plugin, bool) {
	for _, p := range core.RegisteredPlugins() {
		if p.Name == name {
			return p, true
		}
	}
	return core.Plugin{}, false
}
