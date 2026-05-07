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
// **Multi-plugin contract (v1.64+)**: a Job names zero or more
// plugins.
//
//   - Empty Plugins slice → run every registered plugin
//     (default-build registry; offensive plugins gated by
//     `-tags offensive`).
//   - Non-empty Plugins → run only the named subset.
//
// For each plugin × target, the runner dispatches the probe iff
// the plugin's DefaultPort matches the target's Port (the same
// port-match heuristic discover --hosts uses; matches operator
// mental model that the modbus plugin probes 502 etc.).
//
// **Stats semantics under multi-plugin**:
//
//   - TargetsSeen: len(parsed targets). The shape of the input
//     the operator submitted.
//   - TargetsScanned: count of (target, plugin) **probe
//     attempts** — events drained from scanner.Run output.
//     A target probed by 3 plugins counts as 3.
//   - FindingsCount: total findings produced.
//
// Probe-attempts (rather than unique-targets-touched) keeps the
// drain loop simple and matches "how much work did this scan
// do" intuition. Operators who want unique targets can derive
// it from Job.Input.
type defaultScanRunner struct {
	// concurrency caps the scanner's MaxConcurrentTargets per
	// plugin run. Zero → 100. Each plugin gets its own
	// scanner.Scanner; the cap is per-plugin, not global, so a
	// 5-plugin job at concurrency=100 has up to 500 in-flight
	// dials. Operators tune via --scan-pool indirectly (worker
	// pool concurrency × per-plugin cap = ceiling).
	concurrency int
}

// Sentinel errors.
var (
	// ErrRunnerNoMatchingPlugins means the Job's plugin list
	// (or "all" via empty list) produced zero plugin × target
	// matches. Common cause: targets all on a port no plugin
	// claims.
	ErrRunnerNoMatchingPlugins = errors.New("scan runner: no plugin matches any target's port (empty Plugins runs everything; check DefaultPort vs target ports)")
	// ErrRunnerUnknownPlugin means a named plugin isn't in the
	// registry (typo / build-tag mismatch).
	ErrRunnerUnknownPlugin = errors.New("scan runner: plugin not found in registry")
)

// Run implements scanorch.JobRunner. Multi-plugin steps:
//
//  1. Resolve plugin set: empty Plugins → all registered;
//     else look each name up.
//  2. Parse Job.Input via the existing inputParseOpts
//     dispatcher.
//  3. For each plugin, filter targets by port match.
//  4. For each plugin with non-empty matches, run scanner.Run
//     and drain into shared Stats counters + per-plugin
//     findings counter. Call report on every drain event so
//     the dashboard sees mid-scan progress (v1.65+).
//  5. If no plugin × target combo fired, return
//     ErrRunnerNoMatchingPlugins (the operator submitted a job
//     that genuinely had zero work).
//
// Returns final Stats + per-plugin findings breakdown
// (v1.66+). The breakdown only includes plugins that
// dispatched at least one probe; empty-matches plugins are
// absent from the map.
func (r *defaultScanRunner) Run(ctx context.Context, job scanorch.Job, report scanorch.ProgressReporter) (scanorch.Stats, map[string]int, error) {
	if report == nil {
		report = func(scanorch.Stats, map[string]int) {}
	}
	plugins, err := resolvePlugins(job.Plugins)
	if err != nil {
		return scanorch.Stats{}, nil, err
	}
	targets, err := parseInput(ctx, inputParseOpts{InputKind: job.Input, DefaultPort: job.DefaultPort})
	if err != nil {
		return scanorch.Stats{}, nil, fmt.Errorf("scan runner: parse input: %w", err)
	}
	stats := scanorch.Stats{TargetsSeen: len(targets)}
	if len(targets) == 0 {
		return stats, nil, nil
	}
	state := newRunState(r.concurrency, len(targets))
	dispatched := state.dispatchAll(ctx, plugins, targets, report)
	if dispatched == 0 {
		return stats, nil, ErrRunnerNoMatchingPlugins
	}
	stats.FindingsCount = int(state.findingsCount.Load())
	stats.TargetsScanned = int(state.targetsScanned.Load())
	return stats, state.snapshotByPlugin(), nil
}

// runState carries the per-Run mutable state — the shared
// counters + per-plugin findings map. Extracted to keep
// defaultScanRunner.Run under the funlen 60-line ceiling.
type runState struct {
	concurrency    int
	targetsTotal   int
	findingsCount  atomic.Int64
	targetsScanned atomic.Int64
	// byPlugin: each drainPluginRun owns its own atomic in this
	// map; a snapshot is built for the report callback by
	// reading all entries. The map itself is only mutated under
	// the runner's single-goroutine outer loop (one plugin at a
	// time, sync), so no extra mutex is needed.
	byPlugin map[string]*atomic.Int64
}

func newRunState(concurrency, targetsTotal int) *runState {
	if concurrency <= 0 {
		concurrency = 100
	}
	return &runState{
		concurrency:  concurrency,
		targetsTotal: targetsTotal,
		byPlugin:     make(map[string]*atomic.Int64),
	}
}

// snapshotByPlugin builds a {plugin → findings} snapshot from
// the per-plugin atomics. Caller owns the returned map.
func (s *runState) snapshotByPlugin() map[string]int {
	out := make(map[string]int, len(s.byPlugin))
	for name, c := range s.byPlugin {
		out[name] = int(c.Load())
	}
	return out
}

// dispatchAll iterates plugins, runs scanner.Run per matched
// plugin, and drains. Returns the count of plugins that
// dispatched at least one probe attempt.
func (s *runState) dispatchAll(ctx context.Context, plugins []core.Plugin, targets []core.Target, report scanorch.ProgressReporter) int {
	emit := func() {
		report(scanorch.Stats{
			TargetsSeen:    s.targetsTotal,
			TargetsScanned: int(s.targetsScanned.Load()),
			FindingsCount:  int(s.findingsCount.Load()),
		}, s.snapshotByPlugin())
	}
	var dispatched int
	for _, plugin := range plugins {
		matching := filterByPort(targets, plugin)
		if len(matching) == 0 {
			continue
		}
		dispatched++
		var perPlugin atomic.Int64
		s.byPlugin[plugin.Name] = &perPlugin
		scn := scanner.New(scanner.Options{MaxConcurrentTargets: s.concurrency})
		findings, errs := scn.Run(ctx, matching, plugin.Factory().Probe)
		drainPluginRun(findings, errs, &s.findingsCount, &s.targetsScanned, &perPlugin, emit)
	}
	return dispatched
}

// resolvePlugins turns the Job.Plugins names into a Plugin
// slice. Empty input returns every registered plugin.
func resolvePlugins(names []string) ([]core.Plugin, error) {
	if len(names) == 0 {
		return core.RegisteredPlugins(), nil
	}
	out := make([]core.Plugin, 0, len(names))
	for _, name := range names {
		p, ok := lookupPluginByName(name)
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrRunnerUnknownPlugin, name)
		}
		out = append(out, p)
	}
	return out, nil
}

// filterByPort returns the subset of targets whose Port matches
// the plugin's DefaultPort. A plugin with DefaultPort=0
// (banner-style probe-anywhere) matches every target.
func filterByPort(targets []core.Target, plugin core.Plugin) []core.Target {
	if plugin.DefaultPort == 0 {
		return targets
	}
	out := make([]core.Target, 0, len(targets))
	for _, t := range targets {
		if t.Port == plugin.DefaultPort {
			out = append(out, t)
		}
	}
	return out
}

// drainPluginRun consumes one plugin's scanner.Run output to
// completion, accumulating into the shared atomic counters.
// Probe errors count as targetsScanned (we tried) but not
// findingsCount. perPlugin tracks this single plugin's
// findings (v1.66+). After every event, emit() is called so
// the listener gets a fresh Stats snapshot. Listeners are
// responsible for throttling — the runner fires unconditionally
// (matches the v1.65 ProgressReporter contract).
func drainPluginRun(findings <-chan core.Finding, errs <-chan error, findingsCount, targetsScanned, perPlugin *atomic.Int64, emit func()) {
	for findings != nil || errs != nil {
		select {
		case _, ok := <-findings:
			if !ok {
				findings = nil
				continue
			}
			findingsCount.Add(1)
			targetsScanned.Add(1)
			perPlugin.Add(1)
			emit()
		case _, ok := <-errs:
			if !ok {
				errs = nil
				continue
			}
			targetsScanned.Add(1)
			emit()
		}
	}
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
