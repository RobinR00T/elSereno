package main

import (
	"context"
	"errors"
	"fmt"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"local/elsereno/internal/audit"
	"local/elsereno/internal/core"
)

// newAuditServeCmd is `elsereno audit serve` — the cross-process
// audit-chain coordinator (v1.26 chunk 1). Listens on a Unix
// domain socket; emitter processes (other elsereno verbs)
// connect via audit.Client and fan-in entries through this
// single serialised writer.
//
// Why a daemon vs the v1.15-chunk-4 flock: flock serialises but
// every emitter takes the lock + reads the tail to resume the
// chain on every Append. The daemon holds the FileWriter once,
// computes prev_hash in memory for every append, and writes
// once. At SOC scale (many concurrent operators / scanners) the
// daemon avoids N tail-reads per N appends.
//
// Usage:
//
//	elsereno audit serve \
//	    --socket ~/.elsereno/audit.sock \
//	    --output ~/.elsereno/audit.jsonl
//
// SIGINT / SIGTERM trigger a graceful shutdown that closes the
// listener + removes the socket file.
func newAuditServeCmd() *cobra.Command {
	var socketPath, outputPath string
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the centralised audit-chain daemon over a Unix domain socket",
		Long: `Listens on --socket and accepts line-delimited JSON
audit Entries from emitter processes. The daemon owns the
FileWriter pointing at --output and serialises chain order
across all clients.

Cleaner alternative to the v1.15-chunk-4 flock for SOC-scale
fan-in: instead of N tail-reads per N appends, the daemon holds
the prev_hash in memory and writes once.

The socket file is created with mode 0600 + owned by the operator
user. Cross-user fan-in is not in scope (multi-user OIDC is
vNext).

SIGINT / SIGTERM trigger a graceful shutdown.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runAuditServe(cmd, socketPath, outputPath)
		},
	}
	cmd.Flags().StringVar(&socketPath, "socket", "",
		"Unix domain socket path the daemon binds to (required, must be absolute)")
	cmd.Flags().StringVar(&outputPath, "output", "",
		"audit JSONL log path the daemon writes to (required, must be absolute)")
	return cmd
}

func runAuditServe(cmd *cobra.Command, socketPath, outputPath string) error {
	if socketPath == "" {
		return fail(core.ExitUsage, errors.New("--socket is required"))
	}
	if !filepath.IsAbs(socketPath) {
		return fail(core.ExitUsage, fmt.Errorf("--socket %q must be absolute", socketPath))
	}
	if outputPath == "" {
		return fail(core.ExitUsage, errors.New("--output is required"))
	}
	if !filepath.IsAbs(outputPath) {
		return fail(core.ExitUsage, fmt.Errorf("--output %q must be absolute", outputPath))
	}

	w, err := audit.OpenFileWriter(outputPath)
	if err != nil {
		return fail(core.ExitIOErr, fmt.Errorf("open audit writer: %w", err))
	}
	defer func() { _ = w.Close() }()

	srv, err := audit.NewServer(w, socketPath)
	if err != nil {
		return fail(core.ExitIOErr, err)
	}
	defer func() { _ = srv.Close() }()

	cmd.Printf("audit daemon listening on %s\n", srv.SocketPath())
	cmd.Printf("audit log output:        %s\n", outputPath)
	cmd.Printf("send SIGINT or SIGTERM to shut down\n")

	// Trap SIGINT / SIGTERM for graceful shutdown.
	ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ctx) }()

	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, context.Canceled) {
			return fail(core.ExitIOErr, fmt.Errorf("audit serve: %w", err))
		}
	case <-ctx.Done():
		// Give Serve a moment to drain pending Accept loops.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		<-shutdownCtx.Done()
		_ = srv.Close()
	}
	cmd.Printf("audit daemon stopped\n")
	return nil
}
