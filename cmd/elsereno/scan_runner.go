package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"

	"local/elsereno/internal/core"
	"local/elsereno/internal/scanner"
	"local/elsereno/internal/scanorch"
	"local/elsereno/internal/scope"
)

// defaultScanRunner is the cmd-side scanorch.JobRunner that
// turns a queued Job into actual scanner.Run output. It owns the
// imports the orchestration shell deliberately doesn't carry
// (input parsing + plugin-registry lookup + scanner dispatch).
//
// **Multi-plugin contract (v1.64+)**: a Job names zero or more
// plugins.
//
//   - Empty Plugins slice → run every registered plugin EXCEPT OptIn
//     ones (default-build registry; offensive plugins gated by
//     `-tags offensive`; OptIn probes like s7-exposure / opcua-exposure
//     must be named explicitly, never swept by default).
//   - Non-empty Plugins → run only the named subset (OptIn or not).
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
//     attempts**: events drained from scanner.Run output.
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
	// perHost caps the probes in flight against one host (the
	// config's scanner.max_concurrent_per_host); zero means no cap.
	// serve passes the config's values, as scan does (PITF-094).
	perHost int
	// scope, when non-nil, is the same scope.yaml guardrail the CLI
	// applies: targets it rejects are dropped before any dial. A nil
	// scope is a pass-through (no --scope was set on serve). Without
	// this, dashboard/API scans could reach targets the CLI refuses.
	scope *scope.Scope
	// recorder keeps what the scan finds: the run, its findings and
	// their targets (PITF-094). Nil only in tests that do not care.
	recorder runRecorder
}

// runRecorder records what a dashboard scan finds (PITF-094). Until
// 2026-10-17 the runner only counted findings and dropped them, so the
// dashboard's runs and findings panels never showed a scan.
type runRecorder interface {
	// Start opens the run of a job, before any probe is sent.
	Start(ctx context.Context, job scanorch.Job) (string, error)
	// Record keeps one finding with the target it was probed on.
	Record(ctx context.Context, runID string, f core.Finding, t core.Target) error
	// Finish closes the run with its status (completed, error,
	// cancelled) and the per-severity counts.
	Finish(ctx context.Context, runID, status string, counts map[string]int)
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
	// Apply the scope guardrail before anything is dialled, mirroring
	// the CLI (cmd_scan). filterByScope is a pass-through when r.scope
	// is nil, so this is a no-op unless serve was started with --scope.
	targets = filterByScope(r.scope, targets)
	stats := scanorch.Stats{TargetsSeen: len(targets)}
	if len(targets) == 0 {
		return stats, nil, nil
	}
	if !anyPluginMatches(plugins, targets) {
		// No run is opened for a job with nothing to probe.
		return stats, nil, ErrRunnerNoMatchingPlugins
	}
	state := newRunState(r.concurrency, r.perHost, len(targets))
	// runErr stays set until Run reaches its end, so a panic closes
	// the run as error rather than completed.
	runErr := errRunAborted
	if r.recorder != nil {
		// The run is opened before any probe, so a database that cannot
		// record it stops the scan before it sends traffic.
		runID, serr := r.recorder.Start(ctx, job)
		if serr != nil {
			return stats, nil, fmt.Errorf("scan runner: start run: %w", serr)
		}
		state.recordTo(r.recorder, runID)
		defer func() { r.recorder.Finish(ctx, runID, state.runStatus(ctx, runErr), state.severityCounts()) }()
	}
	dispatched := state.dispatchAll(ctx, plugins, targets, report)
	stats.FindingsCount = int(state.findingsCount.Load())
	stats.TargetsScanned = int(state.targetsScanned.Load())
	if rerr := state.recordErr(); rerr != nil {
		// Probing on while nothing can be kept is wasted traffic: the
		// first failed write cancelled the rest, as in the CLI.
		runErr = fmt.Errorf("scan runner: record findings: %w", rerr)
		return stats, state.snapshotByPlugin(), runErr
	}
	if dispatched == 0 {
		runErr = ErrRunnerNoMatchingPlugins
		return stats, nil, runErr
	}
	runErr = nil
	return stats, state.snapshotByPlugin(), nil
}

// errRunAborted is the status a run is closed with when Run does not
// reach its end (a panic outside the probes).
var errRunAborted = errors.New("scan runner: run aborted")

// safeProbe turns a panic in a probe into that probe's error. The
// scanner runs probes in goroutines without recover, so one panic on
// hostile bytes took the whole serve process down, every running job
// with it (PITF-094 audit; PITF-080 had such a panic in slmp).
func safeProbe(plugin string, probe scanner.Probe) scanner.Probe {
	return func(ctx context.Context, t core.Target) (f *core.Finding, err error) {
		defer func() {
			if r := recover(); r != nil {
				f, err = nil, fmt.Errorf("scan runner: %s probe panicked on %s: %v", plugin, netip.AddrPortFrom(t.Address, uint16(t.Port)), r)
			}
		}()
		return probe(ctx, t)
	}
}

// anyPluginMatches reports whether some plugin would probe some target.
func anyPluginMatches(plugins []core.Plugin, targets []core.Target) bool {
	for _, p := range plugins {
		if len(filterByPort(targets, p)) > 0 {
			return true
		}
	}
	return false
}

// runState carries the per-Run mutable state, the shared
// counters + per-plugin findings map. Extracted to keep
// defaultScanRunner.Run under the funlen 60-line ceiling.
type runState struct {
	concurrency    int
	perHost        int
	targetsTotal   int
	findingsCount  atomic.Int64
	targetsScanned atomic.Int64
	// byPlugin: each drainPluginRun owns its own atomic in this
	// map; a snapshot is built for the report callback by
	// reading all entries. The map itself is only mutated under
	// the runner's single-goroutine outer loop (one plugin at a
	// time, sync), so no extra mutex is needed.
	byPlugin map[string]*atomic.Int64

	// recorder and runID, when set, receive every finding with its
	// target. The first failed write is kept in recErr and cancels
	// the remaining probes. bySeverity feeds the run's end event.
	recorder   runRecorder
	runID      string
	mu         sync.Mutex
	recErr     error
	bySeverity map[string]int
}

func (s *runState) recordTo(r runRecorder, runID string) {
	s.recorder, s.runID = r, runID
	s.bySeverity = make(map[string]int)
}

func (s *runState) recordErr() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.recErr
}

func (s *runState) severityCounts() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]int, len(s.bySeverity))
	for k, v := range s.bySeverity {
		out[k] = v
	}
	return out
}

// runStatus is the status the run is closed with: cancelled when the
// job's context ended, error when the runner failed, else completed.
func (s *runState) runStatus(ctx context.Context, runErr error) string {
	switch {
	case ctx.Err() != nil:
		return "cancelled"
	case runErr != nil || s.recordErr() != nil:
		return "error"
	default:
		return "completed"
	}
}

// recording wraps a probe so each finding is recorded with its target
// before it is counted. The first failed write cancels the run.
func (s *runState) recording(probe scanner.Probe, cancel context.CancelFunc) scanner.Probe {
	if s.recorder == nil {
		return probe
	}
	return func(ctx context.Context, t core.Target) (*core.Finding, error) {
		f, err := probe(ctx, t)
		if err != nil || f == nil {
			return f, err
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.recErr != nil {
			return f, nil
		}
		if werr := s.recorder.Record(ctx, s.runID, *f, t); werr != nil {
			s.recErr = werr
			cancel()
			return f, nil
		}
		s.bySeverity[string(f.Severity)]++
		return f, nil
	}
}

func newRunState(concurrency, perHost, targetsTotal int) *runState {
	if concurrency <= 0 {
		concurrency = 100
	}
	return &runState{
		concurrency:  concurrency,
		perHost:      perHost,
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
		scn := scanner.New(scanner.Options{MaxConcurrentTargets: s.concurrency, MaxConcurrentPerHost: s.perHost})
		runCtx, cancel := context.WithCancel(ctx)
		findings, errs := scn.Run(runCtx, matching, s.recording(safeProbe(plugin.Name, plugin.Factory().Probe), cancel))
		drainPluginRun(findings, errs, &s.findingsCount, &s.targetsScanned, &perPlugin, emit)
		cancel()
		if s.recordErr() != nil {
			break
		}
	}
	return dispatched
}

// resolvePlugins turns the Job.Plugins names into a Plugin slice. Empty
// input returns every registered plugin EXCEPT the OptIn ones: a deep or
// intrusive probe (s7-exposure, opcua-exposure) must be named explicitly,
// never swept across every target by a "run everything" job. Naming a
// plugin explicitly always runs it, OptIn or not.
func resolvePlugins(names []string) ([]core.Plugin, error) {
	if len(names) == 0 {
		all := core.RegisteredPlugins()
		out := make([]core.Plugin, 0, len(all))
		for _, p := range all {
			if p.OptIn {
				continue
			}
			out = append(out, p)
		}
		return out, nil
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
// responsible for throttling, the runner fires unconditionally
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
