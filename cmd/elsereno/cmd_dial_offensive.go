//go:build offensive

package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"local/elsereno/internal/core"
	"local/elsereno/internal/scope"
	"local/elsereno/offensive/dial"
	"local/elsereno/offensive/sandbox"
)

func newDialCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dial",
		Short: "Dial guard (ADR-041) — individual validation + batch wardial",
	}
	cmd.AddCommand(newDialValidateCmd())
	cmd.AddCommand(newDialBatchCmd())
	cmd.AddCommand(newDialWardialCmd())
	return cmd
}

// newDialValidateCmd preserves the original single-number check
// under a `validate` subcommand so existing operator muscle memory
// works; the former top-level verb body is unchanged.
func newDialValidateCmd() *cobra.Command {
	var number, scopePath string
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate one number against the dial guard",
		Long: `Runs the dial guard (ADR-041):

  1. Normalise the number (strip +, 00, non-digit punctuation).
  2. Reject if ≤3 digits (unbypassable — emergency / short codes).
  3. Reject if scope.yaml's blocked_numbers matches (prefix or exact).
  4. (not in this verb) triple-confirm via offensive.confirm.Authorize.

Use this for dry-run validation before invoking a delivery channel.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if number == "" {
				return fail(core.ExitUsage, fmt.Errorf("--number is required"))
			}
			sc, err := loadScope(scopePath)
			if err != nil {
				return err
			}
			norm, err := dial.Validate(number, sc)
			switch {
			case errors.Is(err, dial.ErrShortNumber):
				cmd.Printf("DENY — ≤3-digit hard block (normalised=%q)\n", norm)
				return fail(core.ExitError, err)
			case errors.Is(err, dial.ErrBlockedByScope):
				cmd.Printf("DENY — scope.yaml blocked_numbers (normalised=%q)\n", norm)
				return fail(core.ExitError, err)
			case errors.Is(err, dial.ErrEmpty):
				cmd.Println("DENY — empty / non-digit number")
				return fail(core.ExitUsage, err)
			case err != nil:
				return fail(core.ExitError, err)
			}
			cmd.Printf("ALLOW (pending triple-confirm) — normalised=%q\n", norm)
			cmd.Println()
			cmd.Println("Next: run `elsereno dial batch ...` for a multi-number dry-run with audit chain.")
			return nil
		},
	}
	cmd.Flags().StringVar(&number, "number", "", "E.164 number to validate")
	cmd.Flags().StringVar(&scopePath, "scope", "", "optional scope.yaml path")
	return cmd
}

// newDialBatchCmd classifies a list of numbers against the dial
// guard + scope + ≤3-digit hard block and appends one
// `offensive_dial` audit entry per decision. Default mode is
// preview (dry-run) — v1.2 wires in actual PSTN / VoIP delivery
// when the modem / VoIP backends land. The seccomp `dial`
// sandbox is installed before the batch runs so the process
// cannot spawn fresh network sockets while classifying.
func newDialBatchCmd() *cobra.Command {
	var scopePath, numbersFile, disposition string
	cmd := &cobra.Command{
		Use:   "batch",
		Short: "Wardial batch — validate + audit every number in a file or stdin",
		Long: `Reads one number per line from --numbers-file (or stdin if omitted)
and appends one audit chain entry per number (allow / short /
blocked / empty / error). Default disposition is "preview"; pass
--disposition delivery-requested to record dispatch intent (the
actual hardware dial arrives with v1.2 VoIP / modem backends).

The seccomp-bpf "dial" profile is installed before the batch so
the process cannot open new network sockets during classification
(ADR-042). On non-Linux the sandbox degrades to
"unavailable" and the batch still runs.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			sc, err := loadScope(scopePath)
			if err != nil {
				return err
			}
			input, cleanup, err := openNumbersInput(numbersFile)
			if err != nil {
				return err
			}
			defer cleanup()

			rt, err := newAuditOnlyRuntime()
			if err != nil {
				return err
			}
			defer rt.Close()
			if err := rt.ApplySandbox(cmd.Context(), sandbox.ProfileDial); err != nil {
				return fail(core.ExitSoftware, fmt.Errorf("sandbox: %w", err))
			}
			b := dial.Batch{
				Scope:       sc,
				Writer:      rt.Writer,
				Actor:       rt.Actor,
				Disposition: disposition,
			}
			results, err := b.Run(cmd.Context(), input)
			if err != nil {
				return fail(core.ExitError, err)
			}
			printBatchSummary(cmd, results, rt.AuditPath())
			return nil
		},
	}
	cmd.Flags().StringVar(&scopePath, "scope", "", "optional scope.yaml path")
	cmd.Flags().StringVar(&numbersFile, "numbers-file", "", "file with one number per line (omit for stdin)")
	cmd.Flags().StringVar(&disposition, "disposition", "preview",
		"audit disposition: preview | delivery-requested (actual dial is v1.2)")
	return cmd
}

// loadScope resolves the optional --scope flag into a *scope.Scope.
// Empty path → nil scope (no additional blocked_numbers; the hard
// ≤3-digit block still applies).
func loadScope(path string) (*scope.Scope, error) {
	if path == "" {
		return nil, nil
	}
	sc, err := scope.Load(path)
	if err != nil {
		return nil, fail(core.ExitConfig, err)
	}
	return sc, nil
}

// openNumbersInput resolves the --numbers-file flag into an
// io.Reader + cleanup. Empty path falls back to stdin, which is
// the wardialing workflow when numbers are piped from a
// generator script.
func openNumbersInput(path string) (input interface{ Read(p []byte) (int, error) }, cleanup func(), err error) {
	if path == "" {
		return os.Stdin, func() {}, nil
	}
	// #nosec G304 -- operator-supplied numbers file
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, fail(core.ExitIOErr, fmt.Errorf("open numbers file: %w", err))
	}
	return f, func() { _ = f.Close() }, nil
}

// printBatchSummary renders the per-decision tally + the audit
// path the batch wrote to so operators know where to run
// `elsereno audit verify-file` afterwards.
func printBatchSummary(cmd *cobra.Command, results []dial.BatchResult, auditPath string) {
	s := dial.Summarise(results)
	cmd.Printf("wardial batch — %d numbers classified:\n", s.Total)
	cmd.Printf("  allow:   %d\n", s.Allow)
	cmd.Printf("  short:   %d (≤3-digit hard block)\n", s.Short)
	cmd.Printf("  blocked: %d (scope.blocked_numbers)\n", s.Blocked)
	cmd.Printf("  empty:   %d (non-digit / empty lines)\n", s.Empty)
	if s.Errored > 0 {
		cmd.Printf("  error:   %d\n", s.Errored)
	}
	cmd.Printf("audit chain appended to: %s\n", auditPath)
	cmd.Println("Verify the chain with: elsereno audit verify-file")
}

// wardialFlags bundles the wardial verb's flag state so the
// cobra RunE closure stays under funlen limits.
type wardialFlags struct {
	rangeSpec      string
	numbersPath    string
	scopePath      string
	workers        int
	ratePerSec     float64
	checkpointPath string
	disposition    string
}

// newDialWardialCmd is the v2.37+ wardialing orchestrator verb.
// Differs from `dial batch` in that it adds range-spec
// expansion + concurrency + rate-limiting + resume-from-
// checkpoint. The single-shot `dial batch` is preserved for
// short list-driven workflows.
func newDialWardialCmd() *cobra.Command {
	f := &wardialFlags{}
	cmd := &cobra.Command{
		Use:   "wardial",
		Short: "Concurrent wardialing batch (v2.37+; range expansion + rate-limit + resume)",
		Long: `Like 'dial batch', but with:

  --range A..B    expand a range spec (e.g. 555-0100..555-0199 = 100 numbers)
  --workers N     fan-out classification across N goroutines (clamp 1..32)
  --rate R        global cap of R numbers/second (0 = no limit)
  --checkpoint F  append each completed number to F; on resume,
                  skip lines already in F.

Disposition is "preview" by default (audit-only dry run).
v2.37 ships the orchestration; hardware delivery is still
vNext.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runDialWardial(cmd, f)
		},
	}
	cmd.Flags().StringVar(&f.rangeSpec, "range", "", "range spec (start..end). Mutually exclusive with --numbers-file")
	cmd.Flags().StringVar(&f.numbersPath, "numbers-file", "", "file with one number per line (omit for stdin)")
	cmd.Flags().StringVar(&f.scopePath, "scope", "", "optional scope.yaml path")
	cmd.Flags().IntVar(&f.workers, "workers", 1, "concurrent classification workers (1..32)")
	cmd.Flags().Float64Var(&f.ratePerSec, "rate", 0, "max numbers/second (0 = no limit)")
	cmd.Flags().StringVar(&f.checkpointPath, "checkpoint", "", "append each completed number; resume skips lines in this file")
	cmd.Flags().StringVar(&f.disposition, "disposition", "preview",
		"audit disposition: preview | delivery-requested (actual dial is vNext)")
	return cmd
}

// runDialWardial is the extracted RunE body to satisfy funlen.
// Loads scope + audit + sandbox, opens input (range or file),
// runs the Wardial orchestrator, prints summary.
func runDialWardial(cmd *cobra.Command, f *wardialFlags) error {
	sc, err := loadScope(f.scopePath)
	if err != nil {
		return err
	}
	rt, err := newAuditOnlyRuntime()
	if err != nil {
		return err
	}
	defer rt.Close()
	if err := rt.ApplySandbox(cmd.Context(), sandbox.ProfileDial); err != nil {
		return fail(core.ExitSoftware, fmt.Errorf("sandbox: %w", err))
	}
	var inputR io.Reader
	if f.rangeSpec == "" {
		inR, cleanup, openErr := openNumbersInput(f.numbersPath)
		if openErr != nil {
			return openErr
		}
		defer cleanup()
		inputR = inR
	}
	w := &dial.Wardial{
		Scope:          sc,
		Writer:         rt.Writer,
		Actor:          rt.Actor,
		Disposition:    f.disposition,
		Operation:      "dial_wardial",
		Workers:        f.workers,
		RatePerSecond:  f.ratePerSec,
		CheckpointPath: f.checkpointPath,
	}
	results, err := w.Run(cmd.Context(), f.rangeSpec, inputR)
	if err != nil {
		return fail(core.ExitError, err)
	}
	printBatchSummary(cmd, results, rt.AuditPath())
	return nil
}
