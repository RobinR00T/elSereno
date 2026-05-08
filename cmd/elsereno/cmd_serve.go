//go:build !mini

package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/cobra"

	"local/elsereno/internal/config"
	"local/elsereno/internal/core"
	"local/elsereno/internal/creds"
	"local/elsereno/internal/netutil"
	"local/elsereno/internal/scanorch"
	"local/elsereno/internal/web"
	"local/elsereno/internal/web/stream"
)

func newServeCmd() *cobra.Command {
	var opts serveOpts
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the HTTP dashboard + /api/v1",
		Long: "serve binds the HTTP server. It requires an initialised " +
			"vault (ADR-017) because the CSRF key is derived from the " +
			"master key via HKDF. Non-loopback binds additionally require " +
			"--tls-cert, --tls-key, and --i-know-what-im-doing.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runServe(cmd, opts)
		},
	}
	cmd.Flags().StringVar(&opts.addr, "addr", "", "bind address (default 127.0.0.1:8787)")
	cmd.Flags().StringVar(&opts.tlsCert, "tls-cert", "", "TLS certificate (required for non-loopback)")
	cmd.Flags().StringVar(&opts.tlsKey, "tls-key", "", "TLS key (required for non-loopback)")
	cmd.Flags().BoolVar(&opts.iKnow, "i-know-what-im-doing", false, "acknowledge a non-loopback bind")
	cmd.Flags().StringVar(&opts.scanStore, "scan-store", "off",
		"scan-orchestration backend: off (disabled, 503), memory (in-process, lost on restart), db (postgres-persistent, requires DATABASE_URL)")
	cmd.Flags().IntVar(&opts.scanPool, "scan-pool", 2,
		"concurrent scan-job workers (clamped to [1, 64])")
	addPassphraseFileFlag(cmd, &opts.passphraseFile)
	return cmd
}

type serveOpts struct {
	addr            string
	tlsCert, tlsKey string
	iKnow           bool
	passphraseFile  string
	// scanStore selects the scanorch.Store backend: off | memory | db.
	scanStore string
	// scanPool sets the worker pool concurrency.
	scanPool int
}

func runServe(cmd *cobra.Command, opts serveOpts) error {
	cfg, _, err := loadConfig()
	if err != nil {
		return fail(core.ExitConfig, err)
	}
	v, err := unlockVault(cmd, opts.passphraseFile)
	if err != nil {
		return err
	}

	if opts.addr == "" {
		opts.addr = "127.0.0.1:8787"
	}
	if !isLoopbackAddr(opts.addr) && (opts.tlsCert == "" || opts.tlsKey == "" || !opts.iKnow) {
		return fail(core.ExitUsage,
			fmt.Errorf("non-loopback bind %q requires --tls-cert, --tls-key and --i-know-what-im-doing", opts.addr))
	}

	// Optional DB pool for the /api/v1/findings, /runs, /triage
	// endpoints (v1.2 chunk 1b). If DATABASE_URL isn't set, the
	// pool is nil and those endpoints return 503 — serve still
	// runs.
	pool := maybeOpenPool(cmd, cfg)
	if pool != nil {
		defer pool.Close()
	}

	// v1.63: build the SSE broadcaster up-front so the scan-
	// orchestration wrapper can publish state-change events on
	// the same bus the dashboard listens to.
	broadcaster := stream.New(128)

	scanStore, scheduleStore, stopScan, scanErr := buildScanAndSchedule(cmd.Context(), opts, pool, broadcaster)
	if scanErr != nil {
		return fail(core.ExitUsage, scanErr)
	}
	defer stopScan()

	srvOpts := buildWebOptions(opts, cfg, v, pool, scanStore, scheduleStore, broadcaster)
	srv, err := web.NewServer(srvOpts)
	if err != nil {
		return fail(core.ExitSoftware, err)
	}

	stopAuditTail := startAuditTail(cmd.Context(), srv)
	defer stopAuditTail()

	_, _ = fmt.Fprintf(os.Stderr, "elsereno serve: listening on %s\n", opts.addr)
	if err := srv.Run(cmd.Context()); err != nil &&
		!errors.Is(err, http.ErrServerClosed) && !errors.Is(err, context.Canceled) {
		return fail(core.ExitSoftware, err)
	}
	return nil
}

// buildWebOptions assembles the web.Options struct from the
// runServe scope. Splitting this out keeps runServe's
// cyclomatic complexity below the linter's 15-branch ceiling.
func buildWebOptions(opts serveOpts, cfg config.Config, v *creds.Vault, pool *pgxpool.Pool, scanStore scanorch.Store, scheduleStore scanorch.ScheduleStore, broadcaster *stream.Broadcaster) web.Options {
	out := web.Options{
		Addr:          opts.addr,
		Web:           cfg.Web,
		Vault:         v,
		TLSCert:       opts.tlsCert,
		TLSKey:        opts.tlsKey,
		ScanStore:     scanStore,
		ScheduleStore: scheduleStore,
		Broadcaster:   broadcaster,
	}
	if pool != nil {
		out.Querier = pool
	}
	return out
}

// buildScanAndSchedule wraps buildScanOrchestrator with the
// v1.70 schedule-store + scheduler goroutine. Returns a stop
// closure that the caller defers — handles both the worker
// pool Stop and the scan-store cleanup. Splitting this out
// keeps runServe under the gocyclo 15-branch ceiling.
//
// v1.71: when --scan-store=db, the schedule store is also
// DB-backed so schedules survive serve restart. memory mode
// keeps the in-memory schedule store (matches the single-
// process scan-store choice).
func buildScanAndSchedule(ctx context.Context, opts serveOpts, pool *pgxpool.Pool, broadcaster *stream.Broadcaster) (scanorch.Store, scanorch.ScheduleStore, func(), error) {
	scanStore, scanPool, err := buildScanOrchestrator(ctx, opts, pool, broadcaster)
	if err != nil {
		return nil, nil, func() {}, err
	}
	stop := func() {
		if scanPool != nil {
			scanPool.Stop()
		}
	}
	if scanStore == nil {
		// scan-store=off → no scheduler.
		return nil, nil, stop, nil
	}
	var scheduleStore scanorch.ScheduleStore
	if opts.scanStore == "db" && pool != nil {
		scheduleStore = scanorch.NewDBScheduleStore(pool)
	} else {
		scheduleStore = scanorch.NewMemoryScheduleStore()
	}
	startScheduler(ctx, scheduleStore, scanStore)
	return scanStore, scheduleStore, stop, nil
}

// startScheduler spawns the v1.70 Scheduler goroutine. Tied to
// ctx — cancellation tears it down cleanly. Errors during a
// fire are logged to stderr; the next tick re-evaluates the
// schedule, so a transient Submit failure isn't fatal.
func startScheduler(ctx context.Context, schedStore scanorch.ScheduleStore, scanStore scanorch.Store) {
	sc := &scanorch.Scheduler{
		ScheduleStore: schedStore,
		ScanStore:     scanStore,
		OnFire: func(scheduleID string, job scanorch.Job) {
			_, _ = fmt.Fprintf(os.Stderr,
				"elsereno serve: scheduler fired %s → job %s\n",
				scheduleID, job.ID)
		},
		OnFireError: func(scheduleID string, err error) {
			_, _ = fmt.Fprintf(os.Stderr,
				"elsereno serve: scheduler fire error (sched %s): %v\n",
				scheduleID, err)
		},
	}
	go func() {
		if err := sc.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			_, _ = fmt.Fprintf(os.Stderr,
				"elsereno serve: scheduler exited: %v\n", err)
		}
	}()
}

// startAuditTail spins up the audit-file tailer so offensive
// verbs (which run in a separate process and append to
// ~/.elsereno/audit.jsonl) light up the dashboard's live feed.
// Best-effort: a missing home dir or unreadable audit path
// just means the feed stays quiet for audit events — it does
// NOT block `serve` startup. Returns a stop func that cancels
// the tail goroutine.
func startAuditTail(parent context.Context, srv *web.Server) func() {
	tailCtx, cancelTail := context.WithCancel(parent)
	if path, derr := dashboardAuditPath(); derr == nil {
		go func() {
			_ = stream.TailAudit(tailCtx, srv.Broadcaster(), path, 0)
		}()
	}
	return cancelTail
}

// buildScanOrchestrator constructs the scanorch.Store + Worker
// pool selected by `--scan-store`. Returns (nil, nil, nil) when
// the operator chose `off` — APIV1Deps.ScanStore stays nil and
// /api/v1/scans/ surfaces 503.
//
// db requires a non-nil pgxpool.Pool from maybeOpenPool. memory
// works regardless of DB state (handy for dev runs without
// DATABASE_URL).
//
// v1.63: the chosen store is wrapped with a stream.BroadcastingStore
// so every successful Submit / Transition publishes a
// scan_state_change event on the supplied broadcaster. The same
// wrapped store goes to BOTH the REST handler (APIV1Deps) AND
// the worker pool — so transitions from operator-driven REST
// calls (Submit, Cancel) AND from the worker (Running →
// Completed) all flow through the SSE bus.
func buildScanOrchestrator(ctx context.Context, opts serveOpts, pool *pgxpool.Pool, broadcaster *stream.Broadcaster) (scanorch.Store, *scanorch.Pool, error) {
	var inner scanorch.Store
	switch opts.scanStore {
	case "", "off":
		return nil, nil, nil
	case "memory":
		inner = scanorch.NewMemoryStore()
		_, _ = fmt.Fprintf(os.Stderr,
			"elsereno serve: scan-store=memory; pool=%d (jobs lost on restart)\n", opts.scanPool)
	case "db":
		if pool == nil {
			return nil, nil, fmt.Errorf("--scan-store=db requires DATABASE_URL to be set so the DB pool is open")
		}
		inner = scanorch.NewDBStore(pool)
		_, _ = fmt.Fprintf(os.Stderr,
			"elsereno serve: scan-store=db; pool=%d (jobs survive restart)\n", opts.scanPool)
	default:
		return nil, nil, fmt.Errorf("--scan-store: unknown value %q (off | memory | db)", opts.scanStore)
	}
	store := stream.NewBroadcastingStore(inner, broadcaster)
	// v1.65: progress throttle for mid-run Stats snapshots.
	// Default 500ms cadence — balances "operator sees the
	// counter tick" against "100k-target scan doesn't flood
	// the SSE bus". Attached to the store so terminal
	// transitions clear per-job state.
	progress := stream.NewScanProgressThrottle(broadcaster, 500*time.Millisecond)
	store.AttachProgressThrottle(progress)
	worker := &scanorch.Worker{
		Store:  store,
		Runner: &defaultScanRunner{},
		OnProgress: func(jobID string, s scanorch.Stats, byPlugin map[string]int) {
			progress.Report(jobID, s, byPlugin)
		},
	}
	p := scanorch.NewPool(worker, opts.scanPool)
	p.Start(ctx)
	return store, p, nil
}

// maybeOpenPool opens the DB pool when DATABASE_URL is set; nil
// means "serve without DB-backed findings/runs/triage endpoints".
// Split out of runServe so the gocyclo count on the parent stays
// under the linter's threshold.
func maybeOpenPool(cmd *cobra.Command, cfg config.Config) *pgxpool.Pool {
	if os.Getenv("DATABASE_URL") == "" {
		return nil
	}
	p, perr := openPool(cmd, cfg)
	if perr != nil {
		_, _ = fmt.Fprintf(os.Stderr,
			"elsereno serve: DB pool failed, findings endpoints disabled: %v\n", perr)
		return nil
	}
	return p
}

// dashboardAuditPath returns the conventional audit-log location
// (~/.elsereno/audit.jsonl). Parent-dir creation is the operator's
// responsibility; the file itself is created on demand by the
// first offensive verb to write.
func dashboardAuditPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".elsereno", "audit.jsonl"), nil
}

// unlockVault loads the file-backed vault and sources the
// passphrase either from passphraseFile (when non-empty; ADR-026 /
// PITF-016) or by prompting. Returns the unlocked Vault on success.
//
// Lives in vault_unlock.go (extracted v1.29 chunk 1 so the mini
// build keeps the helper available; cmd_serve.go is `!mini`).

// isLoopbackAddr returns true iff addr binds only to loopback.
// Delegates to netutil.IsLoopbackHostPort which catches every
// IPv6 variant (longform `[0:0:0:0:0:0:0:1]:port`, zone-scoped
// `[::1%lo0]:port`, etc.) — the previous substring-based
// implementation only matched `[::1]:` shortform.
func isLoopbackAddr(addr string) bool {
	return netutil.IsLoopbackHostPort(addr)
}
