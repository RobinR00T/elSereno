package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"local/elsereno/internal/core"
)

// newFingerprintCmd returns the `elsereno fingerprint`
// parent verb. v1.37+: validation harness for the
// ProConOS / GE-SRTP fingerprints + every other plugin.
//
// Why a verb: the v1.28 chunks 1+2 introduced two
// fingerprints whose confidence was rated ~0.7 pending
// "real-PLC validation". Operators can now capture bytes
// from their lab PLC (via Wireshark, netcat, etc.) and
// feed them to this verb to confirm the parser handles
// the response correctly — no DB, no scope, no scan-run
// orchestration required.
//
// The verb spins up a localhost TCP listener that replies
// with the operator-supplied bytes, then drives the
// chosen plugin's Probe through that listener. The
// resulting Finding is printed as JSON (factors, score,
// severity, note) so operators can compare against the
// expected fingerprint or paste into a bug report.
func newFingerprintCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fingerprint",
		Short: "Validate a protocol plugin's fingerprint against captured response bytes",
	}
	cmd.AddCommand(newFingerprintValidateCmd())
	cmd.AddCommand(newFingerprintCaptureCmd())
	return cmd
}

// newFingerprintCaptureCmd returns the `elsereno fingerprint
// capture` sub-verb. v1.38+: opens a localhost TCP listener
// for one connection, drains everything the client sends,
// and writes the bytes to --output. The natural companion to
// `validate --file`: capture from your lab PLC via netcat or
// a python one-liner, then feed the file to validate.
//
// Workflow:
//
//	(window 1) elsereno fingerprint capture --listen :19999 --output cap.bin
//	(window 2) plc-vendor-tool ... | nc -q1 lab-host 19999
//	(window 1) wrote 124 bytes to cap.bin
//	(window 1) elsereno fingerprint validate --plugin proconos --file cap.bin
func newFingerprintCaptureCmd() *cobra.Command {
	var (
		listen     string
		outputPath string
		timeout    time.Duration
	)
	cmd := &cobra.Command{
		Use:   "capture",
		Short: "Capture a single TCP connection's bytes to a file",
		Long: `Opens a localhost TCP listener, accepts one connection,
drains everything the client sends until the client closes, and
writes the bytes to --output. The natural companion to ` + "`validate --file`" + `:
capture from your lab PLC, then feed the file to validate.

  --listen   bind address (e.g. 127.0.0.1:19999 or :19999)
  --output   file to write captured bytes to (created 0600)
  --timeout  upper bound on Accept + Read (default 60s)`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runFingerprintCapture(cmd.Context(), fingerprintCaptureOpts{
				Listen:  listen,
				Output:  outputPath,
				Timeout: timeout,
				Out:     cmd.OutOrStdout(),
			})
		},
	}
	cmd.Flags().StringVar(&listen, "listen", "127.0.0.1:0",
		"bind address (e.g. 127.0.0.1:19999 or :19999); 0 → kernel-picked port (printed on bind)")
	cmd.Flags().StringVar(&outputPath, "output", "",
		"file to write captured bytes to (required; created 0600)")
	cmd.Flags().DurationVar(&timeout, "timeout", 60*time.Second,
		"upper bound on Accept + Read")
	return cmd
}

type fingerprintCaptureOpts struct {
	Listen  string
	Output  string
	Timeout time.Duration
	Out     io.Writer
}

// runFingerprintCapture drives the listen + accept + drain
// loop. Single connection only; closes after the client
// closes (or timeout fires).
func runFingerprintCapture(ctx context.Context, opts fingerprintCaptureOpts) error {
	if opts.Output == "" {
		return fail(core.ExitUsage, errors.New("--output is required"))
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	lc := net.ListenConfig{}
	listener, err := lc.Listen(ctx, "tcp", opts.Listen)
	if err != nil {
		return fail(core.ExitOSErr, fmt.Errorf("listen %s: %w", opts.Listen, err))
	}
	defer func() { _ = listener.Close() }()

	tcpAddr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		return fail(core.ExitSoftware,
			fmt.Errorf("listen: addr type %T is not *net.TCPAddr", listener.Addr()))
	}
	_, _ = fmt.Fprintf(opts.Out, "listening on %s; waiting for one connection (timeout %s)\n",
		tcpAddr.String(), opts.Timeout)

	conn, err := acceptWithCtx(ctx, listener)
	if err != nil {
		return fail(core.ExitError, fmt.Errorf("accept: %w", err))
	}
	defer func() { _ = conn.Close() }()
	_, _ = fmt.Fprintf(opts.Out, "connected from %s; draining bytes…\n", conn.RemoteAddr())

	bytes, err := io.ReadAll(conn)
	if err != nil {
		return fail(core.ExitError, fmt.Errorf("read: %w", err))
	}
	if len(bytes) == 0 {
		return fail(core.ExitError, errors.New("client closed without sending any bytes"))
	}
	if err := os.WriteFile(opts.Output, bytes, 0o600); err != nil {
		return fail(core.ExitOSErr, fmt.Errorf("write %s: %w", opts.Output, err))
	}
	_, _ = fmt.Fprintf(opts.Out, "wrote %d bytes to %s\n", len(bytes), opts.Output)
	return nil
}

// acceptWithCtx wraps net.Listener.Accept with ctx
// cancellation. The standard library doesn't expose a
// context-aware Accept, so we close the listener on ctx
// cancel to force the goroutine to return with a friendly
// "use of closed network connection" error which we
// translate to ctx.Err.
func acceptWithCtx(ctx context.Context, listener net.Listener) (net.Conn, error) {
	type acceptResult struct {
		conn net.Conn
		err  error
	}
	ch := make(chan acceptResult, 1)
	go func() {
		c, err := listener.Accept()
		ch <- acceptResult{conn: c, err: err}
	}()
	select {
	case <-ctx.Done():
		_ = listener.Close()
		// drain the goroutine.
		r := <-ch
		if r.conn != nil {
			_ = r.conn.Close()
		}
		return nil, ctx.Err()
	case r := <-ch:
		return r.conn, r.err
	}
}

// newFingerprintValidateCmd is the workhorse sub-verb.
//
//	elsereno fingerprint validate --plugin proconos \
//	    --file capture.bin
//	elsereno fingerprint validate --plugin gesrtp \
//	    --hex 020201000000010100000000... \
//	    --timeout 3s
func newFingerprintValidateCmd() *cobra.Command {
	var (
		plugin      string
		filePath    string
		hexBlob     string
		timeoutFlag time.Duration
		jsonOut     bool
	)
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Drive a plugin's Probe against captured response bytes",
		Long: `Spins up a localhost TCP listener that replies with the
supplied bytes, calls the chosen plugin's Probe through it,
and prints the resulting Finding.

  --plugin   plugin name (e.g. proconos, gesrtp, modbus, …)
  --file     path to a binary file containing the captured response
  --hex      hex-encoded response bytes (mutually exclusive with --file)
  --timeout  upper bound on Probe (default 5s)
  --json     emit Finding as JSON (default human-readable)

Use cases:
  - validate ProConOS fingerprint against a captured Berghof /
    Lenze hello (v1.28 chunk 1, confidence ~0.7 pending real-
    PLC validation).
  - validate GE-SRTP fw= field extraction against captured
    service-0x21 responses from Mark VIe / RX3i / PACSystems
    (v1.28 chunk 2).
  - regression-pin a vendor's fingerprint by capturing an
    actual response and folding it into your CI fixtures.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runFingerprintValidate(cmd.Context(), fingerprintValidateOpts{
				Plugin:  plugin,
				File:    filePath,
				Hex:     hexBlob,
				Timeout: timeoutFlag,
				JSON:    jsonOut,
				Out:     cmd.OutOrStdout(),
			})
		},
	}
	cmd.Flags().StringVar(&plugin, "plugin", "", "plugin name (required; see `elsereno plugins list`)")
	cmd.Flags().StringVar(&filePath, "file", "", "path to a binary file with the captured response bytes")
	cmd.Flags().StringVar(&hexBlob, "hex", "", "hex-encoded response bytes (whitespace OK; mutually exclusive with --file)")
	cmd.Flags().DurationVar(&timeoutFlag, "timeout", 5*time.Second, "upper bound on Probe")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit Finding as JSON")
	return cmd
}

type fingerprintValidateOpts struct {
	Plugin  string
	File    string
	Hex     string
	Timeout time.Duration
	JSON    bool
	Out     io.Writer
}

// runFingerprintValidate is exported via the verb above and
// also reachable from the test in cmd_fingerprint_test.go.
// Pulled out as a standalone function so tests don't need
// to spin up a full cobra dispatch.
func runFingerprintValidate(ctx context.Context, opts fingerprintValidateOpts) error {
	if opts.Plugin == "" {
		return fail(core.ExitUsage, errors.New("--plugin is required (see `elsereno plugins list`)"))
	}
	if (opts.File == "") == (opts.Hex == "") {
		return fail(core.ExitUsage,
			errors.New("exactly one of --file / --hex is required"))
	}
	bytes, err := loadFingerprintInput(opts)
	if err != nil {
		return fail(core.ExitUsage, err)
	}

	plugin, err := lookupPlugin(opts.Plugin)
	if err != nil {
		return fail(core.ExitUsage, err)
	}

	finding, err := driveProbeAgainstBytes(ctx, plugin.Factory(), bytes, opts.Timeout)
	if err != nil {
		return fail(core.ExitError, fmt.Errorf("probe: %w", err))
	}

	return emitFingerprintFinding(opts.Out, finding, opts.JSON)
}

// loadFingerprintInput resolves --file or --hex to raw bytes.
func loadFingerprintInput(opts fingerprintValidateOpts) ([]byte, error) {
	if opts.File != "" {
		b, err := os.ReadFile(opts.File) // #nosec G304 -- operator-supplied path is intended.
		if err != nil {
			return nil, fmt.Errorf("--file %s: %w", opts.File, err)
		}
		return b, nil
	}
	// strip whitespace so operators can paste pretty-printed hex.
	clean := strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\n', '\r':
			return -1
		}
		return r
	}, opts.Hex)
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("--hex: %w", err)
	}
	if len(b) == 0 {
		return nil, errors.New("--hex: decoded to 0 bytes")
	}
	return b, nil
}

// lookupPlugin finds the plugin by name in the registry. Case-
// folded match so operators don't have to remember the exact
// casing.
func lookupPlugin(name string) (*core.Plugin, error) {
	want := strings.ToLower(name)
	for _, p := range core.RegisteredPlugins() {
		if strings.EqualFold(p.Name, want) {
			pp := p
			return &pp, nil
		}
	}
	known := make([]string, 0)
	for _, p := range core.RegisteredPlugins() {
		known = append(known, p.Name)
	}
	return nil, fmt.Errorf("--plugin %q: unknown (registered: %s)",
		name, strings.Join(known, ", "))
}

// driveProbeAgainstBytes spins up a localhost TCP responder
// that drains whatever the client sends + writes `reply` once,
// then calls plugin.Probe against the listener. Returns the
// resulting Finding.
//
// The listener accepts exactly one connection then closes —
// real probes do a single dial-read-close cycle, which matches
// the responder's lifetime. Wired-aware plugins that read
// multiple frames (e.g. GE-SRTP service-0x21 follow-up) can
// re-emit the same `reply` payload by passing a multi-frame
// blob; we simply write the entire payload + close.
func driveProbeAgainstBytes(ctx context.Context, p core.Protocol, reply []byte, timeout time.Duration) (*core.Finding, error) {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	lc := net.ListenConfig{}
	listener, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}
	defer func() { _ = listener.Close() }()

	go func() {
		conn, aerr := listener.Accept()
		if aerr != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		// Drain whatever the probe sends so the server-side
		// read doesn't block on a half-open connection. We
		// don't care about the request bytes — the operator
		// supplies the response that the plugin would receive
		// from a real PLC.
		go func() {
			buf := make([]byte, 4096)
			for {
				if _, rerr := conn.Read(buf); rerr != nil {
					return
				}
			}
		}()
		_, _ = conn.Write(reply)
	}()

	tcpAddr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		return nil, fmt.Errorf("listen: addr type %T is not *net.TCPAddr", listener.Addr())
	}
	addrPort := tcpAddr.AddrPort()
	target := core.Target{
		Address: netip.AddrFrom4(addrPort.Addr().As4()),
		Port:    core.Port(addrPort.Port()),
	}

	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return p.Probe(probeCtx, target)
}

// emitFingerprintFinding writes the result to out in either
// JSON (--json) or the default human-readable form.
func emitFingerprintFinding(out io.Writer, f *core.Finding, asJSON bool) error {
	if f == nil {
		_, _ = fmt.Fprintln(out, "(no finding)")
		return nil
	}
	if asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]any{
			"protocol":   f.Protocol,
			"severity":   string(f.Severity),
			"score":      f.Score,
			"factors":    f.Factors,
			"created_at": f.CreatedAt.UTC().Format(time.RFC3339Nano),
		})
	}
	_, _ = fmt.Fprintf(out, "protocol: %s\n", f.Protocol)
	_, _ = fmt.Fprintf(out, "severity: %s\n", f.Severity)
	_, _ = fmt.Fprintf(out, "score:    %d\n", f.Score)
	_, _ = fmt.Fprintln(out, "factors:")
	// Stable order so operators copying terminal output to bug
	// reports get diff-friendly text.
	keys := make([]string, 0, len(f.Factors))
	for k := range f.Factors {
		keys = append(keys, k)
	}
	// Manual sort to avoid pulling in sort just for this.
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[j] < keys[i] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	for _, k := range keys {
		_, _ = fmt.Fprintf(out, "  %-15s %d\n", k+":", f.Factors[k])
	}
	return nil
}
