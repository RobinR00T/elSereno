package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/spf13/cobra"

	"local/elsereno/internal/core"
	"local/elsereno/internal/creds"
	"local/elsereno/internal/web"
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

	srv, err := web.NewServer(web.Options{
		Addr:    opts.addr,
		Web:     cfg.Web,
		Vault:   v,
		TLSCert: opts.tlsCert,
		TLSKey:  opts.tlsKey,
	})
	if err != nil {
		return fail(core.ExitSoftware, err)
	}
	_, _ = fmt.Fprintf(os.Stderr, "elsereno serve: listening on %s\n", opts.addr)
	if err := srv.Run(cmd.Context()); err != nil &&
		!errors.Is(err, http.ErrServerClosed) && !errors.Is(err, context.Canceled) {
		return fail(core.ExitSoftware, err)
	}
	return nil
}

// unlockVault loads the file-backed vault and sources the
// passphrase either from passphraseFile (when non-empty; ADR-026 /
// PITF-016) or by prompting. Returns the unlocked Vault on success.
func unlockVault(cmd *cobra.Command, passphraseFile string) (*creds.Vault, error) {
	v, _, err := loadVault(cmd.Context())
	if err != nil {
		return nil, err
	}
	pp, err := readPassphraseFromFileOrPrompt(cmd, passphraseFile, "Vault passphrase: ")
	if err != nil {
		return nil, fail(core.ExitUsage, err)
	}
	if err := v.Unlock(cmd.Context(), pp); err != nil {
		if errors.Is(err, creds.ErrBadPassphrase) {
			return nil, fail(core.ExitNoPerm, err)
		}
		return nil, fail(core.ExitSoftware, err)
	}
	return v, nil
}

// isLoopbackAddr returns true iff addr binds only to loopback.
func isLoopbackAddr(addr string) bool {
	return addr == "" ||
		addr == "127.0.0.1:8787" ||
		addr == "[::1]:8787" ||
		addr == "localhost:8787" ||
		(len(addr) > 10 && (addr[:10] == "127.0.0.1:" || addr[:6] == "[::1]:"))
}
