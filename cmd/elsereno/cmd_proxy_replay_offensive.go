//go:build offensive

package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"local/elsereno/internal/core"
	"local/elsereno/offensive/replay"
)

// newProxyReplayCmd renders an `elsereno-replay/v1` capture
// (produced by `elsereno proxy listen --record FILE`) in a
// human-readable form. v1.30 chunk 2.
//
// The verb is observe-only: no IO replay against a target
// (the recorder package's Replay() callback is library-level
// for tools that want to do replay-against-lab-PLC, but the
// CLI keeps to printing for now — it's the 90% use case
// for forensic post-mortem).
// proxyReplayArgs bundles every CLI flag the verb consumes
// so the RunE closure stays a thin driver. Private to this
// file.
type proxyReplayArgs struct {
	hexLimit             int
	dirFilter            string
	sinceFlag, untilFlag string
}

func newProxyReplayCmd() *cobra.Command {
	var args proxyReplayArgs
	cmd := &cobra.Command{
		Use:   "replay FILE",
		Short: "Print an elsereno-replay/v1 capture (offensive build)",
		Long: `Reads an NDJSON capture produced by ` + "`elsereno proxy listen --record FILE`" +
			` and prints each chunk as a human-readable line:

    [12:00:01.123456] c→u  32B  010100 1c 49 42 45 …
    [12:00:01.123654] u←c  18B  03 06 00 00 00 00 …

The header (first line of the file) is summarised once at the
top so the operator sees protocol + target + start-time.

` + "`--dir client|upstream|both`" + ` filters direction (default both).
` + "`--hex-limit N`" + ` truncates each chunk's hex preview at N bytes
(default 32; 0 = full).
` + "`--since RFC3339`" + ` and ` + "`--until RFC3339`" + ` (v1.44+) narrow the
forensic window to chunks with TS in [since, until]. Either
side is optional; missing means "no bound on that side". RFC3339
nano accepted (microsecond precision common in captures).`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, posArgs []string) error {
			return runProxyReplay(cmd, posArgs[0], args)
		},
	}
	cmd.Flags().IntVar(&args.hexLimit, "hex-limit", 32, "truncate hex preview at N bytes (0 = full)")
	cmd.Flags().StringVar(&args.dirFilter, "dir", "both", "direction: client | upstream | both")
	cmd.Flags().StringVar(&args.sinceFlag, "since", "", "v1.44+: RFC3339 lower bound (inclusive); empty = no bound")
	cmd.Flags().StringVar(&args.untilFlag, "until", "", "v1.44+: RFC3339 upper bound (inclusive); empty = no bound")
	return cmd
}

// runProxyReplay is the RunE body for `elsereno proxy
// replay`. Extracted so newProxyReplayCmd stays under the
// linter's funlen ceiling.
func runProxyReplay(cmd *cobra.Command, path string, args proxyReplayArgs) error {
	window, err := parseTimeWindow(args.sinceFlag, args.untilFlag)
	if err != nil {
		return fail(core.ExitUsage, err)
	}

	hdr, err := replay.SeekHeader(path)
	if err != nil {
		return fail(core.ExitOSErr, fmt.Errorf("replay: %w", err))
	}
	cmd.Printf("# capture %s\n", path)
	cmd.Printf("# protocol  %s\n", hdr.Protocol)
	cmd.Printf("# target    %s\n", hdr.Target)
	cmd.Printf("# started   %s\n", hdr.StartedAt.UTC().Format("2006-01-02T15:04:05.999999Z07:00"))
	if !window.since.IsZero() || !window.until.IsZero() {
		cmd.Printf("# window    %s — %s\n",
			formatWindowSide(window.since, "(open)"),
			formatWindowSide(window.until, "(open)"))
	}
	cmd.Println()

	wantClient, wantUpstream := parseDirFilter(args.dirFilter)
	ctx := cmd.Context()
	err = replay.Replay(ctx, path, func(ev replay.ChunkEvent) error {
		if ev.Dir == replay.DirClientToUpstream && !wantClient {
			return nil
		}
		if ev.Dir == replay.DirUpstreamToClient && !wantUpstream {
			return nil
		}
		if !window.contains(ev.TS) {
			return nil
		}
		cmd.Println(formatChunk(ev, args.hexLimit))
		return nil
	})
	if err != nil {
		return fail(core.ExitError, fmt.Errorf("replay: %w", err))
	}
	return nil
}

// timeWindow is the (since, until) pair the --since/--until
// flags resolve to. Zero time on either side means "no bound".
// `contains` short-circuits to true when both bounds are zero
// so the no-flags path stays free.
type timeWindow struct {
	since, until time.Time
}

// contains reports whether ts falls within [since, until]. A
// zero bound disables that side. ts is also tolerated as zero
// (a ChunkEvent with an unparseable TS would have zero); we
// pass those through so a corrupted line doesn't get filtered
// out silently — the operator notices the bad timestamp in
// the rendered output instead.
func (w timeWindow) contains(ts time.Time) bool {
	if !w.since.IsZero() && !ts.IsZero() && ts.Before(w.since) {
		return false
	}
	if !w.until.IsZero() && !ts.IsZero() && ts.After(w.until) {
		return false
	}
	return true
}

// parseTimeWindow validates --since / --until and resolves
// them to a timeWindow. Both empty → zero-value window
// (contains returns true unconditionally). Either non-empty
// is parsed as RFC3339Nano (the format the recorder writes).
// since > until is rejected explicitly so a typo doesn't
// silently match nothing.
func parseTimeWindow(since, until string) (timeWindow, error) {
	var w timeWindow
	if since != "" {
		t, err := time.Parse(time.RFC3339Nano, since)
		if err != nil {
			return timeWindow{}, fmt.Errorf("--since %q: %w (want RFC3339Nano like 2026-05-04T12:00:00Z)", since, err)
		}
		w.since = t
	}
	if until != "" {
		t, err := time.Parse(time.RFC3339Nano, until)
		if err != nil {
			return timeWindow{}, fmt.Errorf("--until %q: %w (want RFC3339Nano like 2026-05-04T12:00:00Z)", until, err)
		}
		w.until = t
	}
	if !w.since.IsZero() && !w.until.IsZero() && w.since.After(w.until) {
		return timeWindow{}, fmt.Errorf("--since %s is after --until %s (window matches nothing)", w.since.Format(time.RFC3339), w.until.Format(time.RFC3339))
	}
	return w, nil
}

// formatWindowSide renders one bound for the "# window" header
// line. Zero-value bounds get the placeholder so the operator
// sees "(open) — 12:00:00Z" rather than a confusing "0001-…".
func formatWindowSide(t time.Time, placeholder string) string {
	if t.IsZero() {
		return placeholder
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// parseDirFilter maps the --dir flag to a (clientWanted,
// upstreamWanted) pair. Unknown values fall back to both — the
// typical pilot-error mode is a typo, and showing everything is
// safer than showing nothing.
func parseDirFilter(s string) (bool, bool) {
	switch strings.ToLower(s) {
	case "client", "c", "client_to_upstream":
		return true, false
	case "upstream", "u", "upstream_to_client":
		return false, true
	default:
		return true, true
	}
}

// formatChunk renders one ChunkEvent as the canonical line:
//
//	[HH:MM:SS.uuuuuu] c→u  NNB  hex-preview…
func formatChunk(ev replay.ChunkEvent, hexLimit int) string {
	arrow := "c→u"
	if ev.Dir == replay.DirUpstreamToClient {
		arrow = "u→c"
	}
	hex := ev.Hex
	if hexLimit > 0 && len(hex) > hexLimit*2 {
		hex = hex[:hexLimit*2] + "…"
	}
	return fmt.Sprintf("[%s] %s  %5dB  %s",
		ev.TS.UTC().Format("15:04:05.000000"), arrow, ev.Len, hex)
}

// _ tie-up: ensure context import isn't dropped if the
// signature evolves.
var _ context.Context
