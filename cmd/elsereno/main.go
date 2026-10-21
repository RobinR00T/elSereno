package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"local/elsereno/internal/core"
	"local/elsereno/internal/telemetry"
)

// Build-time variables populated via -ldflags.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// Persistent global flags (ADR conventions).
var (
	flagConfig  string
	flagFormat  string
	flagDryRun  bool
	flagQuiet   bool
	flagVerbose bool
)

// dryRunAnnotation marks a command whose RunE honours --dry-run.
const dryRunAnnotation = "elsereno/dry-run"

// honoursDryRun marks cmd as one that implements --dry-run, so the root
// lets the flag through to it.
func honoursDryRun(cmd *cobra.Command) *cobra.Command {
	if cmd.Annotations == nil {
		cmd.Annotations = map[string]string{}
	}
	cmd.Annotations[dryRunAnnotation] = "honoured"
	return cmd
}

// refuseUnhonouredDryRun stops a command that does not implement
// --dry-run before it runs. Until 2026-10-16 those commands ignored the
// flag and acted: `scan --dry-run` scanned, `db migrate up --dry-run`
// migrated (PITF-089). It is the root's PersistentPreRunE, so it only
// runs while no subcommand defines its own persistent pre-run hook
// (dry_run_test.go checks that none does).
func refuseUnhonouredDryRun(cmd *cobra.Command, _ []string) error {
	if !flagDryRun || cmd.Annotations[dryRunAnnotation] == "honoured" {
		return nil
	}
	hint := "only " + strings.Join(dryRunCommands(cmd.Root()), ", ") + " implement it"
	if strings.HasSuffix(cmd.Name(), "dry-run") {
		hint = "this subcommand is already a dry run; drop --dry-run"
	}
	return fail(core.ExitUsage, fmt.Errorf("--dry-run is not implemented by `%s`; nothing was run (%s)",
		cmd.CommandPath(), hint))
}

// dryRunCommands lists the commands marked with honoursDryRun, without
// the root's name, in cobra's (alphabetical) order.
func dryRunCommands(root *cobra.Command) []string {
	var out []string
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		if c.Annotations[dryRunAnnotation] == "honoured" {
			out = append(out, strings.TrimPrefix(c.CommandPath(), root.Name()+" "))
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(root)
	return out
}

// signalExitCode is the exit code for the first signal stored in first.
// signal.NotifyContext and the trap's channel get the same signal, but
// the trap's goroutine may not have stored it yet when the command
// returns; it waits a moment, then falls back to SIGTERM's 143.
func signalExitCode(first *atomic.Value) int {
	for i := 0; i < 100; i++ {
		if sig, ok := first.Load().(os.Signal); ok {
			return exitCodeForSignal(sig)
		}
		time.Sleep(time.Millisecond)
	}
	return 143
}

// exitCodeForSignal returns 128+signum for SIGINT and SIGTERM; 1 otherwise.
func exitCodeForSignal(sig os.Signal) int {
	switch sig {
	case syscall.SIGINT:
		return 130
	case syscall.SIGTERM:
		return 143
	default:
		return 1
	}
}

func main() {
	os.Exit(entrypoint(os.Args[1:]))
}

// entrypoint wires signal handling and dispatches via cobra. Kept separate
// from main() so deferred cleanup runs before os.Exit.
func entrypoint(args []string) int {
	// Redact every standard-logger line at the sink, so a log.Printf
	// anywhere in the binary is far less likely to emit a keyed secret
	// (api-key, bearer, password) or a bare high-entropy token in the
	// clear (PITF-099). It is not a complete net: a low-entropy token
	// such as a hex key tops out near 4.0 bits/byte and slips the
	// bare-token heuristic, and a direct fmt.Fprint to os.Stderr never
	// reaches this sink, so inputs.RedactQuery upstream stays the primary
	// defence. Defence in depth, not a licence to log secrets on purpose.
	log.SetFlags(0)
	log.SetOutput(telemetry.NewRedactWriter(os.Stderr))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Second-signal hard-exit trap. The first signal is kept so a clean
	// completion after it exits 128+signum of that signal.
	sigs := make(chan os.Signal, 2)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigs)
	var first atomic.Value
	go func() {
		first.Store(<-sigs)
		second := <-sigs
		os.Exit(exitCodeForSignal(second))
	}()

	root := newRootCmd()
	root.SetArgs(args)
	root.SetOut(os.Stdout)
	root.SetErr(os.Stderr)
	err := root.ExecuteContext(ctx)

	if ctxErr := ctx.Err(); ctxErr != nil {
		// Context was cancelled by a signal; honour 128+signum on a clean
		// completion (130 for SIGINT, 143 for SIGTERM).
		if err == nil {
			return signalExitCode(&first)
		}
	}

	if err == nil {
		return 0
	}
	// Typed exit code from a subcommand. Print the error so the
	// operator sees *why*: cobra's SilenceErrors:true suppresses
	// its own print, and most call sites of fail() don't print
	// before returning, so without this the binary would exit
	// silently on every typed-exit error path.
	var ce cliError
	if errors.As(err, &ce) {
		if msg := ce.Error(); msg != "" {
			fmt.Fprintln(os.Stderr, "elsereno:", msg)
		}
		return int(ce.code)
	}
	// Cobra itself flagged an usage error.
	if errors.Is(err, errUsage) {
		fmt.Fprintln(os.Stderr, "elsereno:", err)
		return int(core.ExitUsage)
	}
	fmt.Fprintln(os.Stderr, "elsereno:", err)
	return int(core.ExitError)
}

// cliError wraps a sentinel exit code for a subcommand's RunE return.
type cliError struct {
	code core.ExitCode
	err  error
}

func (c cliError) Error() string {
	if c.err == nil {
		return ""
	}
	return c.err.Error()
}

func (c cliError) Unwrap() error { return c.err }

func fail(code core.ExitCode, err error) error { return cliError{code: code, err: err} }

var errUsage = errors.New("usage error")

func newRootCmd() *cobra.Command {
	root := installBanner(&cobra.Command{
		Use:   "elsereno",
		Short: "ICS/OT legacy exposure auditor",
		Long: "elsereno, ICS/OT and legacy-network exposure auditor.\n" +
			"Read LEGAL.md and run `elsereno legal` before first use.",
		SilenceErrors:     true,
		SilenceUsage:      true,
		DisableAutoGenTag: true,
	})

	root.PersistentFlags().StringVar(&flagConfig, "config", "", "path to elsereno.yaml (overrides lookup order)")
	root.PersistentFlags().StringVar(&flagFormat, "format", "", "output format (yaml|json|table|ndjson|csv)")
	root.PersistentFlags().BoolVar(&flagDryRun, "dry-run", false, "simulate side effects; only schedule delete|enable|disable|clone|import|pause-all|resume-all implement it, every other command refuses to run with it")
	root.PersistentPreRunE = refuseUnhonouredDryRun
	root.PersistentFlags().BoolVar(&flagQuiet, "quiet", false, "suppress non-critical output")
	root.PersistentFlags().BoolVar(&flagVerbose, "verbose", false, "verbose logging (debug level)")

	root.AddCommand(newVersionCmd())
	root.AddCommand(newDoctorCmd())
	root.AddCommand(newLegalCmd())
	root.AddCommand(newPluginsCmd())
	root.AddCommand(newConfigCmd())
	root.AddCommand(newScoringCmd())
	root.AddCommand(newVaultCmd())
	root.AddCommand(newCredsCmd())
	root.AddCommand(newDbCmd())
	root.AddCommand(newAuditCmd())
	registerWebVerbs(root)
	root.AddCommand(newScanCmd())
	root.AddCommand(newDiscoverCmd())
	root.AddCommand(newExplainCmd())
	root.AddCommand(newWhyCmd())
	root.AddCommand(newTriageCmd())
	root.AddCommand(newLintCmd())
	root.AddCommand(newFmtCmd())
	root.AddCommand(newBackupCmd())
	root.AddCommand(newTUICmd())
	root.AddCommand(newFingerprintCmd())
	root.AddCommand(newScheduleCmd())
	root.AddCommand(newProfinetCmd())
	root.AddCommand(newGooseCmd())
	root.AddCommand(newModbusCmd())
	root.AddCommand(newOPCUACmd())
	root.AddCommand(newS7Cmd())
	root.AddCommand(newPlaintextCheckCmd())
	root.AddCommand(newStandardsCmd())

	for _, c := range newStubCmds() {
		root.AddCommand(c)
	}

	// offensive subcommands (-tags offensive): write, exploit,
	// harvest, dial. The stub in cmd_offensive_stub.go is a no-op
	// in the default build.
	registerOffensiveCmds(root)

	return root
}
