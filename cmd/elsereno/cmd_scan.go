package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"local/elsereno/internal/config"
	"local/elsereno/internal/core"
	"local/elsereno/internal/inputs/list"
	"local/elsereno/internal/inputs/nmapxml"
	"local/elsereno/internal/inputs/stdin"
	csvout "local/elsereno/internal/outputs/csv"
	ndjsonout "local/elsereno/internal/outputs/ndjson"
	stixout "local/elsereno/internal/outputs/stix"
	"local/elsereno/internal/protocols/banner"
	"local/elsereno/internal/scanner"
	"local/elsereno/internal/scope"
	"local/elsereno/internal/telemetry"
)

func newScanCmd() *cobra.Command {
	var opts scanOpts
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan a set of targets and emit findings",
		Long: "scan reads targets from --input, resolves and dedupes, runs " +
			"concurrent probes against them, and emits findings in the " +
			"format selected by --output-format (ndjson|csv). If a " +
			"scope.yaml is present or --scope is set, targets outside " +
			"scope are rejected.",
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
	cmd.Flags().StringVar(&opts.outputFormat, "output-format", "ndjson", "ndjson|csv")
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
	scn := scanner.New(scanner.Options{
		MaxConcurrentTargets: pickPositive(opts.maxConcurrent, cfg.Scanner.MaxConcurrentTargets),
		MaxConcurrentPerHost: cfg.Scanner.MaxConcurrentPerHost,
		RatePerSecond:        opts.ratePerSec,
		MaxRetries:           opts.retries,
	})
	probe := banner.Default().Probe

	total := int64(len(targets))
	var pb *telemetry.ProgressBar
	if !opts.noProgress {
		pb = telemetry.NewProgress(os.Stderr, total)
	}

	emit, cleanup, err := scanOutput(out, opts.outputFormat)
	if err != nil {
		return err
	}
	defer cleanup()

	findings, errs := scn.Run(ctx, targets, probe)
	produced, err := drainScanChannels(findings, errs, emit, pb)
	if pb != nil {
		pb.Done()
	}
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(os.Stderr, "scan complete: %d findings (from %d targets)\n", produced, total)
	return nil
}

// scanOutput builds an emit func for the selected output format.
// cleanup must be called when draining is done (csv flushes on Close).
func scanOutput(out io.Writer, format string) (func(core.Finding) error, func(), error) {
	switch format {
	case "ndjson":
		w := ndjsonout.NewWriter(out)
		return func(f core.Finding) error { return w.WriteFinding(f, "") }, func() {}, nil
	case "csv":
		w := csvout.NewWriter(out)
		return func(f core.Finding) error {
				return w.WriteFinding(f, "", 0)
			}, func() {
				_ = w.Close()
			}, nil
	case "stix":
		// STIX 2.1 bundle: buffered in memory + flushed on
		// cleanup. v1.15 chunk 3.
		w := stixout.NewWriter(out)
		return func(f core.Finding) error {
				return w.WriteFinding(f, "", 0)
			}, func() {
				_ = w.Close()
			}, nil
	default:
		return nil, nil, fail(core.ExitUsage, fmt.Errorf("unknown --output-format %q (ndjson|csv|stix)", format))
	}
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
func readTargets(ctx context.Context, opts scanOpts) ([]core.Target, error) {
	switch {
	case opts.inputKind == "stdin":
		p, err := portForInput(opts.defaultPort)
		if err != nil {
			return nil, err
		}
		return stdin.Parse(ctx, os.Stdin, list.ParseOptions{DefaultPort: p})
	case strings.HasPrefix(opts.inputKind, "list:"):
		path := strings.TrimPrefix(opts.inputKind, "list:")
		f, err := os.Open(path) // #nosec G304 -- caller-supplied input list path
		if err != nil {
			return nil, err
		}
		defer func() { _ = f.Close() }()
		p, err := portForInput(opts.defaultPort)
		if err != nil {
			return nil, err
		}
		return list.Parse(ctx, f, list.ParseOptions{DefaultPort: p})
	case strings.HasPrefix(opts.inputKind, "nmap:"):
		path := strings.TrimPrefix(opts.inputKind, "nmap:")
		f, err := os.Open(path) // #nosec G304 -- caller-supplied XML path
		if err != nil {
			return nil, err
		}
		defer func() { _ = f.Close() }()
		return nmapxml.Parse(ctx, f)
	case strings.HasPrefix(opts.inputKind, "shodan:"):
		return readTargetsFromProvider(ctx, "shodan",
			strings.TrimPrefix(opts.inputKind, "shodan:"), opts.apiCredsFile)
	case strings.HasPrefix(opts.inputKind, "censys:"):
		return readTargetsFromProvider(ctx, "censys",
			strings.TrimPrefix(opts.inputKind, "censys:"), opts.apiCredsFile)
	case strings.HasPrefix(opts.inputKind, "fofa:"):
		return readTargetsFromProvider(ctx, "fofa",
			strings.TrimPrefix(opts.inputKind, "fofa:"), opts.apiCredsFile)
	case strings.HasPrefix(opts.inputKind, "zoomeye:"):
		return readTargetsFromProvider(ctx, "zoomeye",
			strings.TrimPrefix(opts.inputKind, "zoomeye:"), opts.apiCredsFile)
	case strings.HasPrefix(opts.inputKind, "onyphe:"):
		return readTargetsFromProvider(ctx, "onyphe",
			strings.TrimPrefix(opts.inputKind, "onyphe:"), opts.apiCredsFile)
	case strings.HasPrefix(opts.inputKind, "internetdb:"):
		return readTargetsFromProvider(ctx, "internetdb",
			strings.TrimPrefix(opts.inputKind, "internetdb:"), opts.apiCredsFile)
	default:
		return nil, fmt.Errorf(
			"unknown input kind %q; use list:<path> | nmap:<path> | stdin | shodan:<q> | censys:<q> | fofa:<q> | zoomeye:<q> | onyphe:<q> | internetdb:<ip>",
			opts.inputKind)
	}
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
