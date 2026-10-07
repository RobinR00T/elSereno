package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/spf13/cobra"

	"local/elsereno/internal/config"
	"local/elsereno/internal/core"
	csvout "local/elsereno/internal/outputs/csv"
	ndjsonout "local/elsereno/internal/outputs/ndjson"
	stixout "local/elsereno/internal/outputs/stix"
	"local/elsereno/internal/scanner"
	"local/elsereno/internal/scope"
	"local/elsereno/internal/telemetry"
)

func newScanCmd() *cobra.Command {
	var opts scanOpts
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan a set of targets and emit findings",
		Long: "scan reads targets from --input, resolves and dedupes, and " +
			"probes each target with the protocol plugins whose default " +
			"port matches the target's port (banner, which has no default " +
			"port, probes every target; opt-in plugins such as " +
			"s7-exposure run only when named in --plugin). The same " +
			"per-port dispatch as dashboard scans. Findings are emitted in " +
			"the format selected by --output-format (ndjson|csv|stix), each " +
			"with the target's address and port. If a scope.yaml is present " +
			"or --scope is set, targets outside scope are rejected. To probe " +
			"one plugin on a non-default port, use `fingerprint probe`.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runScan(cmd, opts)
		},
	}
	cmd.Flags().StringVar(&opts.inputKind, "input", "",
		"input source: list:<path> | nmap:<path> | stdin | shodan:<query> | censys:<query> | fofa:<query> | zoomeye:<query> | onyphe:<query>")
	cmd.Flags().StringVar(&opts.apiCredsFile, "api-creds-file", "",
		"YAML file with provider credentials (0600 required); needed when --input uses shodan:/censys:/fofa:/zoomeye:/onyphe:")
	cmd.Flags().StringVar(&opts.scopePath, "scope", "", "path to scope.yaml (optional)")
	cmd.Flags().IntVar(&opts.defaultPort, "default-port", 0, "port applied when a list line has no ':port'")
	cmd.Flags().IntVar(&opts.ratePerSec, "rate", 0, "probe rate limit per second (0 = unlimited)")
	cmd.Flags().IntVar(&opts.maxConcurrent, "max-concurrent", 0, "max concurrent targets (default from config)")
	cmd.Flags().IntVar(&opts.retries, "retries", 2, "retries on ErrTimeout (default 2)")
	cmd.Flags().StringSliceVar(&opts.plugins, "plugin", nil,
		"plugins to run, repeatable or comma-separated (see `elsereno plugins list`); default: every non-opt-in plugin, each on the targets whose port is its default port")
	cmd.Flags().StringVar(&opts.outputFormat, "output-format", "ndjson", "ndjson|csv|stix")
	cmd.Flags().StringVar(&opts.outputPath, "output", "-", "output file (`-` for stdout)")
	cmd.Flags().BoolVar(&opts.noProgress, "no-progress", false, "disable the progress bar")
	return cmd
}

type scanOpts struct {
	inputKind     string
	apiCredsFile  string
	scopePath     string
	defaultPort   int
	ratePerSec    int
	maxConcurrent int
	retries       int
	outputFormat  string
	outputPath    string
	noProgress    bool
	plugins       []string
}

func runScan(cmd *cobra.Command, opts scanOpts) error {
	if opts.inputKind == "" {
		return fail(core.ExitUsage, fmt.Errorf("--input required; e.g. list:targets.txt, nmap:out.xml, stdin"))
	}

	cfg, _, err := loadConfig()
	if err != nil {
		return fail(core.ExitConfig, err)
	}

	s, err := scope.Load(opts.scopePath)
	if err != nil {
		return fail(core.ExitConfig, err)
	}

	targets, err := readTargets(cmd.Context(), opts)
	if err != nil {
		return fail(core.ExitDataErr, err)
	}
	targets = filterByScope(s, targets)
	if len(targets) == 0 {
		return fail(core.ExitNoInput, fmt.Errorf("no targets after scope filter"))
	}

	out, closer, err := openOutput(opts)
	if err != nil {
		return fail(core.ExitIOErr, err)
	}
	defer func() { _ = closer() }()

	return execScan(cmd.Context(), cfg, opts, targets, out)
}

func execScan(ctx context.Context, cfg config.Config, opts scanOpts, targets []core.Target, out io.Writer) error {
	plugins, err := resolvePlugins(opts.plugins)
	if err != nil {
		return fail(core.ExitUsage, err)
	}
	runs, total := planScan(plugins, targets)
	if len(runs) == 0 {
		return fail(core.ExitNoInput, fmt.Errorf("%w; to probe a plugin on a non-default port use `elsereno fingerprint probe --plugin <name> --target host:port`", ErrRunnerNoMatchingPlugins))
	}

	warnOptInAnyPort(os.Stderr, runs)

	write, cleanup, err := scanOutput(out, opts.outputFormat)
	if err != nil {
		return err
	}
	defer cleanup()

	var pb *telemetry.ProgressBar
	if !opts.noProgress {
		pb = telemetry.NewProgress(os.Stderr, total)
	}

	produced, err := runPlans(ctx, cfg, opts, runs, write, pb)
	if pb != nil {
		pb.Done()
	}
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(os.Stderr, "scan complete: %d findings (from %d targets, %d probes across %d plugins)\n",
		produced, len(targets), total, len(runs))
	return nil
}

// runPlans runs each plugin over its targets in turn and writes every
// finding with the target it was probed on. A core.Finding does not
// carry its target, so the write happens inside the probe wrapper,
// where the target is known, under a mutex (the writers are not safe
// for concurrent use); the drain only counts. An earlier version looked
// the target up by finding ID afterwards, which breaks when a plugin's
// ID does not depend on the target: banner's was sha256(banner bytes),
// identical for every silent port, so findings were written with
// another host's address (caught by review on 2026-10-07).
func runPlans(ctx context.Context, cfg config.Config, opts scanOpts, runs []pluginRun,
	write func(core.Finding, core.Target) error, pb *telemetry.ProgressBar) (int64, error) {
	var (
		mu       sync.Mutex
		writeErr error
		produced int64
	)
	countOnly := func(core.Finding) error { return nil }
	for _, r := range runs {
		scn := scanner.New(scanner.Options{
			MaxConcurrentTargets: pickPositive(opts.maxConcurrent, cfg.Scanner.MaxConcurrentTargets),
			MaxConcurrentPerHost: cfg.Scanner.MaxConcurrentPerHost,
			RatePerSecond:        opts.ratePerSec,
			MaxRetries:           opts.retries,
		})
		probe := r.plugin.Factory().Probe
		// The first failed write cancels the run: probing on while
		// nothing can be recorded (a full disk on a /16) is wasted
		// traffic against the targets.
		runCtx, cancel := context.WithCancel(ctx)
		writing := func(ctx context.Context, t core.Target) (*core.Finding, error) {
			f, err := probe(ctx, t)
			if err != nil || f == nil {
				return f, err
			}
			mu.Lock()
			defer mu.Unlock()
			if writeErr == nil {
				if writeErr = write(*f, t); writeErr != nil {
					cancel()
				}
			}
			return f, nil
		}
		findings, errs := scn.Run(runCtx, r.targets, writing)
		n, err := drainScanChannels(findings, errs, countOnly, pb)
		cancel()
		produced += n
		mu.Lock()
		werr := writeErr
		mu.Unlock()
		if werr != nil {
			return produced, fail(core.ExitIOErr, werr)
		}
		if err != nil {
			return produced, err
		}
	}
	return produced, nil
}

// warnOptInAnyPort warns when a named opt-in plugin has no default port
// (s7-exposure, opcua-exposure, codesys-active): like banner it then
// probes every listed target, whatever its port, which is rarely what
// the operator means. Binding them to their protocol's port is an open
// decision (TODO-vNext); until then the operator is told.
func warnOptInAnyPort(w io.Writer, runs []pluginRun) {
	for _, r := range runs {
		if r.plugin.OptIn && r.plugin.DefaultPort == 0 {
			_, _ = fmt.Fprintf(w, "warn: opt-in plugin %s has no default port and will probe all %d listed targets, whatever their port; list only its protocol's hosts, or use `elsereno fingerprint probe --plugin %s --target host:port`\n",
				r.plugin.Name, len(r.targets), r.plugin.Name)
		}
	}
}

// pluginRun is one plugin and the targets it probes.
type pluginRun struct {
	plugin  core.Plugin
	targets []core.Target
}

// planScan pairs each plugin with the targets on its default port, the
// same per-port dispatch as dashboard scans (defaultScanRunner); banner
// (no default port) gets every target. It returns the runs and the total
// number of probes. Until 2026-10-07 the CLI ran banner alone, although
// this command's manual promised per-port protocol plugins.
func planScan(plugins []core.Plugin, targets []core.Target) ([]pluginRun, int64) {
	var runs []pluginRun
	var total int64
	for _, p := range plugins {
		matching := filterByPort(targets, p)
		if len(matching) == 0 {
			continue
		}
		runs = append(runs, pluginRun{plugin: p, targets: matching})
		total += int64(len(matching))
	}
	return runs, total
}

// scanOutput builds the writer for the selected output format: it
// receives each finding with the target it was probed on. cleanup must
// be called when draining is done (csv flushes on Close).
func scanOutput(out io.Writer, format string) (func(core.Finding, core.Target) error, func(), error) {
	switch format {
	case "ndjson":
		w := ndjsonout.NewWriter(out)
		return func(f core.Finding, t core.Target) error {
			return w.WriteFinding(f, targetAddr(t), int(t.Port))
		}, func() {}, nil
	case "csv":
		w := csvout.NewWriter(out)
		return func(f core.Finding, t core.Target) error {
				return w.WriteFinding(f, targetAddr(t), t.Port)
			}, func() {
				_ = w.Close()
			}, nil
	case "stix":
		// STIX 2.1 bundle: buffered in memory + flushed on
		// cleanup. v1.15 chunk 3.
		w := stixout.NewWriter(out)
		return func(f core.Finding, t core.Target) error {
				return w.WriteFinding(f, targetAddr(t), int(t.Port))
			}, func() {
				_ = w.Close()
			}, nil
	default:
		return nil, nil, fail(core.ExitUsage, fmt.Errorf("unknown --output-format %q (ndjson|csv|stix)", format))
	}
}

// targetAddr renders a target's address, or "" for the zero Target (a
// finding whose origin was not recorded).
func targetAddr(t core.Target) string {
	if !t.Address.IsValid() {
		return ""
	}
	return t.Address.String()
}

// drainScanChannels folds findings + errors into `emit` until both
// channels close. Non-fatal errors go to stderr; ErrNoTargets is
// fatal.
func drainScanChannels(findings <-chan core.Finding, errs <-chan error, emit func(core.Finding) error, pb *telemetry.ProgressBar) (int64, error) {
	var produced int64
	for findings != nil || errs != nil {
		select {
		case f, ok := <-findings:
			if !ok {
				findings = nil
				continue
			}
			if err := emit(f); err != nil {
				return produced, fail(core.ExitIOErr, err)
			}
			produced++
			if pb != nil {
				pb.Inc(1)
			}
		case e, ok := <-errs:
			if !ok {
				errs = nil
				continue
			}
			if errors.Is(e, scanner.ErrNoTargets) {
				return produced, fail(core.ExitNoInput, e)
			}
			_, _ = fmt.Fprintln(os.Stderr, "warn:", e)
			if pb != nil {
				pb.Inc(1)
			}
		}
	}
	return produced, nil
}

// readTargets parses --input and returns a slice of core.Target.
// Thin shim over parseInput (cmd_input_parse.go) so the same
// dispatcher serves cmd_scan + cmd_tui (v1.31+).
func readTargets(ctx context.Context, opts scanOpts) ([]core.Target, error) {
	return parseInput(ctx, inputParseOpts{
		InputKind:    opts.inputKind,
		DefaultPort:  opts.defaultPort,
		APICredsFile: opts.apiCredsFile,
	})
}

// filterByScope drops targets rejected by the scope. A nil scope is a
// pass-through.
func filterByScope(s *scope.Scope, targets []core.Target) []core.Target {
	if s == nil {
		return targets
	}
	out := make([]core.Target, 0, len(targets))
	for _, t := range targets {
		if err := s.Check(t); err == nil {
			out = append(out, t)
		}
	}
	return out
}

// openOutput prepares the sink. Returning a closer keeps the io.Writer
// abstraction clean for callers.
func openOutput(opts scanOpts) (io.Writer, func() error, error) {
	if opts.outputPath == "" || opts.outputPath == "-" {
		return os.Stdout, func() error { return nil }, nil
	}
	// #nosec G304 -- caller-supplied output path
	f, err := os.Create(opts.outputPath)
	if err != nil {
		return nil, nil, err
	}
	return f, f.Close, nil
}

func pickPositive(a, b int) int {
	if a > 0 {
		return a
	}
	return b
}

// portForInput converts a CLI int to a core.Port with explicit bounds
// checking. Zero means "no default port" and is valid.
func portForInput(n int) (core.Port, error) {
	if n == 0 {
		return 0, nil
	}
	return core.NewPort(n)
}
