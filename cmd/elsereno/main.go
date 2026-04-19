package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"local/elsereno/internal/core"
)

// Build-time variables populated via -ldflags.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// exitCodeForSignal returns 128+signum for SIGINT and SIGTERM.
// Anything else falls back to a conservative 1.
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

// entrypoint wires signal handling and dispatches; kept separate from
// main() so deferred cleanup runs before os.Exit.
func entrypoint(args []string) int {
	// Root context cancelled on SIGINT or SIGTERM. A second signal during
	// drain triggers immediate exit with the same 128+signum code.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Hard-exit trap on second signal.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs // first — handled by NotifyContext above
		second := <-sigs
		// The user insisted; leave immediately.
		os.Exit(exitCodeForSignal(second))
	}()

	code := run(ctx, args)
	if err := ctx.Err(); err != nil && code == 0 {
		// Context was cancelled by a signal; honour 128+signum if we
		// have a clean (0) exit. Default to SIGTERM (143) since we
		// cannot recover the specific signal here.
		code = 143
	}
	return code
}

// run dispatches the top-level verb. F0 wires a handful of working verbs
// and stubs the rest; the dispatch will be replaced by cobra in F1.
func run(ctx context.Context, args []string) int {
	if len(args) == 0 {
		usage(os.Stderr)
		return int(core.ExitUsage)
	}

	verb := args[0]
	rest := args[1:]

	switch verb {
	case "version":
		return cmdVersion()
	case "help", "-h", "--help":
		usage(os.Stdout)
		return 0
	case "doctor":
		return cmdDoctor(ctx, rest)
	case "legal":
		return cmdLegal(ctx, rest)
	case "plugins":
		return cmdPlugins(ctx, rest)

	// F0 stubs — return EX_TEMPFAIL until wired in later phases.
	case "init", "db", "audit", "vault", "creds", "token", "config",
		"serve", "completion", "scan", "repl", "proxy", "triage",
		"diff", "explain", "why", "lint", "fmt", "gen-man":
		fmt.Fprintf(os.Stderr, "elsereno: %q is planned for a later phase (F0 stub)\n", verb)
		return int(core.ExitTempFail)

	default:
		fmt.Fprintf(os.Stderr, "elsereno: unknown command %q\n", verb)
		usage(os.Stderr)
		return int(core.ExitUsage)
	}
}

func cmdVersion() int {
	fmt.Printf("elsereno %s\ncommit %s\nbuilt %s\n", version, commit, date)
	return 0
}

func cmdLegal(_ context.Context, _ []string) int {
	fmt.Println("ElSereno — acceptable use policy")
	fmt.Println("See LEGAL.md for the full text.")
	fmt.Println("By using ElSereno you acknowledge authorisation, GDPR,")
	fmt.Println("and jurisdiction-specific law (Spain/EU, US CFAA, etc.).")
	return 0
}

func cmdDoctor(_ context.Context, _ []string) int {
	fmt.Println("elsereno doctor — F0 placeholder")
	fmt.Println("cross-platform preflight will check:")
	fmt.Println("  go runtime, postgres connectivity/TLS, nmap,")
	fmt.Println("  CAP_NET_RAW/root, dns/idn, ntp, memguard mlock,")
	fmt.Println("  vault status, ipv6, disk, external creds endpoints.")
	return 0
}

func cmdPlugins(_ context.Context, args []string) int {
	fs := flag.NewFlagSet("plugins", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return int(core.ExitUsage)
	}

	plugins := core.RegisteredPlugins()
	if len(plugins) == 0 {
		fmt.Println("no plugins registered in this build")
		fmt.Println("(default build is read-only; rebuild with -tags offensive to add offensive plugins)")
		return 0
	}
	for _, p := range plugins {
		fmt.Printf("%-10s  %s\n", p.Name, p.Description)
	}
	return 0
}

const usageText = `elsereno — ICS/OT legacy exposure auditor

Usage:
  elsereno <command> [options]

Commands (F0 functional):
  version, help, doctor, legal, plugins

Commands (F0 stub → implemented in later phases):
  init, serve, db, audit, vault, creds, token, config,
  scan, repl, proxy, triage, diff, explain, why,
  lint, fmt, completion, gen-man

See ` + "`elsereno legal`" + ` and LEGAL.md before first use.
`

func usage(w *os.File) {
	_, _ = fmt.Fprint(w, usageText)
}
