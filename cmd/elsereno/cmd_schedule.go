package main

// v2.3+ — `elsereno schedule` CLI verb.
//
// Hits the local serve over HTTP rather than embedding the
// schedule store directly. Reasons:
//
//   - Schedules live in the serve process (memory-mode) or the
//     DB the serve owns. Letting a CLI verb open its own
//     connection to the same DB invites two-writers footguns.
//   - The HTTP path validates auth via the same middleware the
//     dashboard uses, so the CLI inherits whatever policy the
//     operator configured.
//   - Operators wanting to script against the API can grep the
//     `--url` flag for a sanity test ("does my Bearer token
//     work?") before writing curl.
//
// Default URL is the dashboard default 127.0.0.1:8787; override
// via `--url` or `ELSERENO_URL` env. Bearer token via `--token`
// or `ELSERENO_TOKEN` env; `~/.elsereno/token` file is the
// fallback for unattended workflows (file mode 0600).

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// scheduleClientOpts is the shared shape for every `schedule …`
// verb. Populated by PreRunE from the per-verb cobra flags +
// env vars + the ~/.elsereno/token fallback file.
type scheduleClientOpts struct {
	URL   string
	Token string
}

const (
	envScheduleURL     = "ELSERENO_URL"
	envScheduleToken   = "ELSERENO_TOKEN"
	defaultScheduleURL = "http://127.0.0.1:8787"
	// Output format identifiers used by --format consumers.
	scheduleFormatJSON   = "json"
	scheduleFormatNDJSON = "ndjson"
)

// newScheduleCmd builds the `schedule` verb tree.
func newScheduleCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "schedule",
		Short: "Manage scheduled scans via the local serve (v2.3+)",
	}
	cmd.PersistentFlags().String("url", "", "serve URL (default $ELSERENO_URL or http://127.0.0.1:8787)")
	cmd.PersistentFlags().String("token", "", "Bearer token (default $ELSERENO_TOKEN or ~/.elsereno/token)")
	cmd.AddCommand(newScheduleListCmd())
	cmd.AddCommand(newScheduleGetCmd())
	cmd.AddCommand(newScheduleDeleteCmd())
	cmd.AddCommand(newScheduleStatsCmd())
	cmd.AddCommand(newScheduleExportCmd())
	return cmd
}

// resolveScheduleOpts reads --url + --token, falling back to
// env vars + the on-disk token file. Returns a complete
// scheduleClientOpts ready for httpDo.
func resolveScheduleOpts(cmd *cobra.Command) scheduleClientOpts {
	url, _ := cmd.Flags().GetString("url")
	if url == "" {
		url = os.Getenv(envScheduleURL)
	}
	if url == "" {
		url = defaultScheduleURL
	}
	token, _ := cmd.Flags().GetString("token")
	if token == "" {
		token = os.Getenv(envScheduleToken)
	}
	if token == "" {
		token = readTokenFile()
	}
	return scheduleClientOpts{URL: strings.TrimRight(url, "/"), Token: token}
}

// readTokenFile reads ~/.elsereno/token if it exists + mode is
// 0600. Returns empty string on any error (the caller falls back
// to no auth — the dashboard ignores Bearer when auth-mode is
// off).
func readTokenFile() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	path := filepath.Join(home, ".elsereno", "token")
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}
	if info.Mode().Perm()&0o077 != 0 {
		// Refuse to use a world/group-readable token file —
		// matches the SECURITY.md guideline against token
		// leaks via file modes.
		_, _ = fmt.Fprintf(os.Stderr, "elsereno schedule: ~/.elsereno/token has loose mode %o; skipping\n", info.Mode().Perm())
		return ""
	}
	body, err := os.ReadFile(path) // #nosec G304 — fixed path under operator's HOME.
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(body))
}

// httpDo executes one HTTP request against the serve, applying
// the Bearer token + standard timeouts. Closes the response
// body internally + returns the bytes. Non-2xx status codes
// surface as errors with the response body embedded — callers
// that need status-specific branching can switch on
// errors.Is(...). Today every caller just propagates.
func httpDo(opts scheduleClientOpts, method, path string) ([]byte, error) {
	req, err := http.NewRequest(method, opts.URL+path, http.NoBody) //nolint:noctx // CLI; long timeouts are fine.
	if err != nil {
		return nil, err
	}
	if opts.Token != "" {
		req.Header.Set("Authorization", "Bearer "+opts.Token)
	}
	if method == http.MethodPost || method == http.MethodPut {
		req.Header.Set("Content-Type", "application/json")
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("elsereno schedule: HTTP %s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("elsereno schedule: read body: %w", err)
	}
	if resp.StatusCode >= 400 {
		return respBody, fmt.Errorf("elsereno schedule: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	return respBody, nil
}

// envelopeRaw is the shared response wrapper. Data is left as
// raw JSON so per-verb parsers can decode the right concrete
// type.
type envelopeRaw struct {
	Schema string          `json:"schema"`
	Data   json.RawMessage `json:"data"`
}

func newScheduleListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all schedules",
		RunE: func(cmd *cobra.Command, _ []string) error {
			opts := resolveScheduleOpts(cmd)
			body, err := httpDo(opts, http.MethodGet, "/api/v1/schedules")
			if err != nil {
				return err
			}
			return writeScheduleList(cmd.OutOrStdout(), body)
		},
	}
}

// writeScheduleList emits the list in one of: table (default;
// human-readable), json, ndjson. Honours --format from the
// root command.
func writeScheduleList(out io.Writer, body []byte) error {
	switch strings.ToLower(flagFormat) {
	case scheduleFormatJSON:
		_, err := out.Write(body)
		return err
	case scheduleFormatNDJSON:
		var env envelopeRaw
		if err := json.Unmarshal(body, &env); err != nil {
			return err
		}
		var items []json.RawMessage
		if err := json.Unmarshal(env.Data, &items); err != nil {
			return err
		}
		for _, it := range items {
			_, _ = out.Write(it)
			_, _ = fmt.Fprintln(out)
		}
		return nil
	default:
		return renderScheduleTable(out, body)
	}
}

func renderScheduleTable(out io.Writer, body []byte) error {
	var env struct {
		Data []scheduleListRow `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return err
	}
	tw := newAlignedWriter(out)
	defer tw.Flush()
	_, _ = fmt.Fprintln(tw, "ID\tNAME\tCADENCE\tENABLED\tLAST FIRED")
	for _, s := range env.Data {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%v\t%s\n",
			s.ID, s.Name, s.cadence(), s.Enabled, s.lastFired())
	}
	return nil
}

type scheduleListRow struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	IntervalSeconds int       `json:"interval_seconds"`
	CronExpr        string    `json:"cron_expr"`
	Timezone        string    `json:"timezone"`
	Enabled         bool      `json:"enabled"`
	LastFiredAt     time.Time `json:"last_fired_at"`
}

func (s scheduleListRow) cadence() string {
	if s.CronExpr != "" {
		if s.Timezone != "" {
			return "cron=" + s.CronExpr + " (" + s.Timezone + ")"
		}
		return "cron=" + s.CronExpr
	}
	return "interval=" + strconv.Itoa(s.IntervalSeconds) + "s"
}

func (s scheduleListRow) lastFired() string {
	if s.LastFiredAt.IsZero() {
		return "—"
	}
	return s.LastFiredAt.UTC().Format(time.RFC3339)
}

func newScheduleGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get <id>",
		Short: "Get one schedule by ID",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := resolveScheduleOpts(cmd)
			body, err := httpDo(opts, http.MethodGet, "/api/v1/schedules/"+args[0])
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			// Pretty-print JSON by default; raw on --format=json.
			if strings.ToLower(flagFormat) == scheduleFormatJSON {
				_, err = out.Write(body)
				return err
			}
			var pretty bytes.Buffer
			if err := json.Indent(&pretty, body, "", "  "); err != nil {
				// Body wasn't valid JSON. Write raw + surface
				// the error so the caller knows their schedule
				// payload was malformed.
				_, _ = out.Write(body)
				return fmt.Errorf("indent body: %w", err)
			}
			_, _ = out.Write(pretty.Bytes())
			_, _ = fmt.Fprintln(out)
			return nil
		},
	}
}

func newScheduleDeleteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete <id>",
		Short: "Delete a schedule (with confirmation)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := resolveScheduleOpts(cmd)
			yes, _ := cmd.Flags().GetBool("yes")
			if !yes && !flagDryRun {
				return errors.New("elsereno schedule delete: pass --yes to confirm (or --dry-run)")
			}
			if flagDryRun {
				_, _ = fmt.Fprintf(cmd.OutOrStdout(), "[dry-run] would DELETE %s\n", args[0])
				return nil
			}
			if _, err := httpDo(opts, http.MethodDelete, "/api/v1/schedules/"+args[0]); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "deleted %s\n", args[0])
			return nil
		},
	}
	cmd.Flags().Bool("yes", false, "skip the confirmation prompt")
	return cmd
}

func newScheduleStatsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "stats <id>",
		Short: "Show aggregate run-stats for a schedule (v2.2+)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := resolveScheduleOpts(cmd)
			days, _ := cmd.Flags().GetInt("days")
			path := "/api/v1/schedules/" + args[0] + "/stats"
			if days > 0 {
				path += "?days=" + strconv.Itoa(days)
			}
			body, err := httpDo(opts, http.MethodGet, path)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if strings.ToLower(flagFormat) == scheduleFormatJSON {
				_, err = out.Write(body)
				return err
			}
			return renderStatsHuman(out, body)
		},
	}
	cmd.Flags().Int("days", 7, "window in days (1..365)")
	return cmd
}

func renderStatsHuman(out io.Writer, body []byte) error {
	var env struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return err
	}
	tw := newAlignedWriter(out)
	defer tw.Flush()
	keys := []string{
		"window_days", "total_runs", "completed", "failed",
		"cancelled", "running", "queued", "success_rate",
		"avg_duration_seconds", "avg_findings_per_run",
		"total_findings",
	}
	for _, k := range keys {
		_, _ = fmt.Fprintf(tw, "%s\t%v\n", k, env.Data[k])
	}
	return nil
}

func newScheduleExportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export schedules (csv|ndjson|json) for DR backup (v1.97+)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			opts := resolveScheduleOpts(cmd)
			format, _ := cmd.Flags().GetString("format")
			if format == "" {
				format = scheduleFormatNDJSON
			}
			path := "/api/v1/schedules/export?format=" + format
			body, err := httpDo(opts, http.MethodGet, path)
			if err != nil {
				return err
			}
			_, err = cmd.OutOrStdout().Write(body)
			return err
		},
	}
	cmd.Flags().String("format", "ndjson", "export format (csv|ndjson|json)")
	return cmd
}

// newAlignedWriter buffers tab-separated rows + pads each
// column to the widest cell on Flush. Dependency-free
// alternative to tabwriter for the small CLI output footprint
// these verbs need.
func newAlignedWriter(out io.Writer) *alignedWriter {
	return &alignedWriter{out: out, buf: &bytes.Buffer{}}
}

type alignedWriter struct {
	out io.Writer
	buf *bytes.Buffer
}

func (a *alignedWriter) Write(p []byte) (int, error) {
	return a.buf.Write(p)
}

func (a *alignedWriter) Flush() {
	lines := strings.Split(strings.TrimRight(a.buf.String(), "\n"), "\n")
	rows := make([][]string, 0, len(lines))
	for _, l := range lines {
		rows = append(rows, strings.Split(l, "\t"))
	}
	widths := map[int]int{}
	for _, r := range rows {
		for i, c := range r {
			if len(c) > widths[i] {
				widths[i] = len(c)
			}
		}
	}
	for _, r := range rows {
		for i, c := range r {
			pad := 0
			if i != len(r)-1 {
				pad = widths[i] - len(c) + 2
			}
			_, _ = a.out.Write([]byte(c))
			if pad > 0 {
				_, _ = a.out.Write([]byte(strings.Repeat(" ", pad)))
			}
		}
		_, _ = a.out.Write([]byte("\n"))
	}
}
