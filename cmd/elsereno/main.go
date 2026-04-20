package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"local/elsereno/internal/core"
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
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Second-signal hard-exit trap.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
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
		// completion. Default to SIGTERM (143).
		if err == nil {
			return 143
		}
	}

	if err == nil {
		return 0
	}
	// Already-printed errors from subcommands returning a typed ExitCode.
	var ce cliError
	if errors.As(err, &ce) {
		return int(ce.code)
	}
	// Cobra itself flagged an usage error.
	if errors.Is(err, errUsage) {
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
	root := &cobra.Command{
		Use:   "elsereno",
		Short: "ICS/OT legacy exposure auditor",
		Long: "elsereno — ICS/OT and legacy-network exposure auditor.\n" +
			"Read LEGAL.md and run `elsereno legal` before first use.",
		SilenceErrors:     true,
		SilenceUsage:      true,
		DisableAutoGenTag: true,
	}

	root.PersistentFlags().StringVar(&flagConfig, "config", "", "path to elsereno.yaml (overrides lookup order)")
	root.PersistentFlags().StringVar(&flagFormat, "format", "", "output format (yaml|json|table|ndjson|csv)")
	root.PersistentFlags().BoolVar(&flagDryRun, "dry-run", false, "simulate side effects without performing them")
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
	root.AddCommand(newServeCmd())
	root.AddCommand(newScanCmd())
	root.AddCommand(newExplainCmd())
	root.AddCommand(newWhyCmd())
	root.AddCommand(newTriageCmd())
	root.AddCommand(newLintCmd())
	root.AddCommand(newFmtCmd())
	root.AddCommand(newAPICmd())
	root.AddCommand(newBackupCmd())

	for _, c := range newStubCmds() {
		root.AddCommand(c)
	}

	// offensive subcommands (-tags offensive): write, exploit,
	// harvest, dial. The stub in cmd_offensive_stub.go is a no-op
	// in the default build.
	registerOffensiveCmds(root)

	return root
}
