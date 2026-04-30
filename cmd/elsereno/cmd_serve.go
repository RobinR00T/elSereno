//go:build !mini

package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/cobra"

	"local/elsereno/internal/config"
	"local/elsereno/internal/core"
	"local/elsereno/internal/netutil"
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
	addPassphraseFileFlag(cmd, &opts.passphraseFile)
	return cmd
}

type serveOpts struct {
	addr            string
	tlsCert, tlsKey string
	iKnow           bool
	passphraseFile  string
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

	srvOpts := web.Options{
		Addr:    opts.addr,
		Web:     cfg.Web,
		Vault:   v,
		TLSCert: opts.tlsCert,
		TLSKey:  opts.tlsKey,
	}
	if pool != nil {
		srvOpts.Querier = pool
	}
	srv, err := web.NewServer(srvOpts)
	if err != nil {
		return fail(core.ExitSoftware, err)
	}

	// Spin up the audit-file tailer so offensive verbs (which run
	// in a separate process and append to ~/.elsereno/audit.jsonl)
	// light up the dashboard's live feed. Best-effort: a missing
	// home dir or unreadable audit path just means the feed stays
	// quiet for audit events — it does NOT block `serve` startup.
	tailCtx, cancelTail := context.WithCancel(cmd.Context())
	defer cancelTail()
	if path, derr := dashboardAuditPath(); derr == nil {
		go func() {
			_ = stream.TailAudit(tailCtx, srv.Broadcaster(), path, 0)
		}()
	}

	_, _ = fmt.Fprintf(os.Stderr, "elsereno serve: listening on %s\n", opts.addr)
	if err := srv.Run(cmd.Context()); err != nil &&
		!errors.Is(err, http.ErrServerClosed) && !errors.Is(err, context.Canceled) {
		return fail(core.ExitSoftware, err)
	}
	return nil
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
