//go:build !mini

package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"local/elsereno/internal/core"
	"local/elsereno/internal/protocols/banner"
	"local/elsereno/internal/tui"
	"local/elsereno/internal/tui/feeds"
)

// newTUICmd registers `elsereno tui` — the interactive
// terminal UI. Four modes selected by flag:
//
//   - (no flag)        interactive — opens the panes with an
//     empty feed; the operator verifies the
//     program runs but no events flow until
//     they restart with --input or another
//     mode flag.
//   - --input list:F   v1.30+: scan from inside the TUI.
//     Loads targets from F + spawns a
//     scanner.Scanner; FindingMsg per finding,
//     ScanProgressMsg as the bar advances.
//   - --replay FILE    NDJSON capture playback. Pairs with
//     `elsereno scan --output-format ndjson`.
//   - --feed -         live NDJSON pipe (stdin). Pairs with the
//     same scan emitter, streamed.
//   - --watch URL      remote SSE consumer. Read-only client
//     for the dashboard's /api/v1/stream.
//
// The TUI is purely additive: every existing batch verb (scan,
// write, exploit, harvest, dial, audit, proxy listen, …)
// keeps its current behaviour. The TUI is opt-in via this
// dedicated verb.
//
// Build tag: `//go:build !mini`. The mini variant gets a stub
// in cmd_tui_mini.go that prints "TUI not available in mini
// build" and exits with EX_UNAVAILABLE (69).
func newTUICmd() *cobra.Command {
	var args pickFeedArgs
	cmd := &cobra.Command{
		Use:   "tui",
		Short: "Interactive terminal UI (default + offensive builds; not in mini)",
		Long: `Open the interactive ElSereno TUI. Five modes:

  - interactive (default): empty panes; useful sanity check.
  - --input KIND: scan from inside the TUI (v1.30+ list, v1.31+
    full kind set). Same kinds as the batch ` + "`scan`" + ` verb:
    list:FILE, nmap:FILE, stdin, shodan:Q, censys:Q, fofa:Q,
    zoomeye:Q, onyphe:Q, internetdb:IP. API-keyed kinds need
    --api-creds-file. Findings populate the panes live.
  - --replay FILE.ndjson: review a pre-recorded NDJSON capture.
  - --feed -: consume NDJSON from stdin (pairs with the batch
    scan verb's --output-format ndjson).
  - --watch URL --bearer TOKEN: subscribe to a remote
    dashboard's SSE feed (read-only).

Tab cycles focus between panes; j/k navigate the findings
table; q quits; / filters the audit pane substring.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			mode, feed, err := pickFeed(cmd.Context(), args)
			if err != nil {
				return fail(core.ExitUsage, err)
			}
			runOpts, err := openRecordSink(args.recordPath)
			if err != nil {
				return fail(core.ExitOSErr, err)
			}
			ctx := cmd.Context()
			if err := tui.RunWithOpts(ctx, mode, feed, os.Stdout, os.Stdin, runOpts); err != nil {
				return fail(core.ExitSoftware, fmt.Errorf("tui: %w", err))
			}
			return nil
		},
	}
	registerTUIFlags(cmd, &args)
	return cmd
}

// registerTUIFlags attaches every flag onto cmd. Extracted from
// newTUICmd so the parent stays under funlen as new flags land.
func registerTUIFlags(cmd *cobra.Command, args *pickFeedArgs) {
	cmd.Flags().StringVar(&args.inputKind, "input", "",
		"v1.30+: scan from inside the TUI. Same kinds as `elsereno scan` (list:<path> | nmap:<path> | stdin | shodan:<q> | censys:<q> | fofa:<q> | zoomeye:<q> | onyphe:<q> | internetdb:<ip>) — v1.31+.")
	cmd.Flags().Uint16Var(&args.defaultPort, "default-port", 0,
		"v1.30+: default port for --input list / stdin entries that omit one (host-only lines)")
	cmd.Flags().StringVar(&args.apiCredsFile, "api-creds-file", "",
		"v1.31+: 0600 YAML file with provider creds (shodan/censys/fofa/zoomeye/onyphe). Same shape as `elsereno scan --api-creds-file`. Ignored for non-keyed kinds (list/nmap/stdin/internetdb).")
	cmd.Flags().StringVar(&args.replayPath, "replay", "",
		"NDJSON capture file to replay (mutually exclusive with --feed and --watch)")
	cmd.Flags().StringVar(&args.feedFlag, "feed", "",
		"NDJSON feed source (only `-` for stdin is supported; use --replay for files)")
	cmd.Flags().StringVar(&args.watchURL, "watch", "",
		"dashboard SSE URL to consume (e.g. https://host:8443/api/v1/stream)")
	cmd.Flags().StringVar(&args.watchBearer, "bearer", "",
		"Bearer token for --watch URL (required for non-loopback targets)")
	cmd.Flags().StringVar(&args.recordPath, "record", "",
		"v1.41+: tee every event the TUI receives onto FILE as `elsereno-tui-record/v1` NDJSON. Symmetric counterpart to --replay. Useful for screen-recording / training / forensics. File created 0600.")
	cmd.Flags().Float64Var(&args.rate, "rate", 0,
		"v1.43+: slow-motion playback rate in events per second (only meaningful for --replay or --feed -; 0 = as fast as possible). Useful for demos where a long capture should pace itself for the audience.")
}

// pickFeedArgs bundles the CLI flags pickFeed consumes so its
// signature stays under the linter's argument-count limit. The
// struct is private to cmd_tui.go.
type pickFeedArgs struct {
	replayPath   string
	feedFlag     string
	watchURL     string
	watchBearer  string
	inputKind    string
	defaultPort  uint16
	apiCredsFile string
	recordPath   string  // v1.41+
	rate         float64 // v1.43+
}

// openRecordSink resolves --record to a tui.RunOpts struct.
// Empty path → zero-RunOpts (recording disabled). Non-empty
// path → opens the file 0600; the runner closes it via the
// recorder.
func openRecordSink(path string) (tui.RunOpts, error) {
	if path == "" {
		return tui.RunOpts{}, nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600) // #nosec G304 -- operator-supplied --record path
	if err != nil {
		return tui.RunOpts{}, fmt.Errorf("--record %s: %w", path, err)
	}
	return tui.RunOpts{Record: f}, nil
}

// pickFeed maps the CLI flags to a tui.Feed + Mode. Mutual
// exclusion is enforced — each --replay / --feed / --watch /
// --input excludes the others. No flag → interactive mode with
// the empty feed (sanity-check shape).
func pickFeed(ctx context.Context, a pickFeedArgs) (tui.Mode, tui.Feed, error) {
	hasReplay := a.replayPath != ""
	hasFeed := a.feedFlag != ""
	hasWatch := a.watchURL != ""
	hasInput := a.inputKind != ""
	if (boolToInt(hasReplay) + boolToInt(hasFeed) + boolToInt(hasWatch) + boolToInt(hasInput)) > 1 {
		return "", nil, errors.New("tui: --input, --replay, --feed, --watch are mutually exclusive")
	}
	switch {
	case hasReplay:
		// Pre-flight stat. We don't open here — the feed
		// goroutine does that — but a missing file is the
		// common operator typo, and surfacing it before the
		// alt screen takes over saves them from a confusing
		// "feed closed with error" line on a still-blank TUI.
		if info, statErr := os.Stat(a.replayPath); statErr != nil {
			return "", nil, fmt.Errorf("tui: --replay: %w", statErr)
		} else if info.IsDir() {
			return "", nil, fmt.Errorf("tui: --replay: %s is a directory", a.replayPath)
		}
		return tui.ModeReplay, feeds.Replay{Path: a.replayPath, Rate: a.rate}, nil
	case hasFeed:
		// Only `-` is supported (stdin). `--feed FILE` is
		// redundant with `--replay FILE`; rejecting it here
		// keeps the two flags' intent distinct (replay = file
		// playback; feed = live producer).
		if a.feedFlag != "-" {
			return "", nil, fmt.Errorf("tui: --feed accepts only `-` (stdin); use --replay for files (got %q)", a.feedFlag)
		}
		return tui.ModeFeed, feeds.Stdin{In: os.Stdin, Rate: a.rate}, nil
	case hasWatch:
		// --bearer is required for any non-loopback target;
		// `serve` rejects unauthenticated stream subscribes.
		// We don't enforce here (loopback is permitted); the
		// runtime will surface 401 fast via authError.
		return tui.ModeWatch, feeds.Watch{
			URL:    a.watchURL,
			Bearer: a.watchBearer,
		}, nil
	case hasInput:
		feed, err := buildInteractiveFeed(ctx, a.inputKind, a.defaultPort, a.apiCredsFile)
		if err != nil {
			return "", nil, err
		}
		return tui.ModeInteractive, feed, nil
	}
	// Default: interactive mode with the empty feed.
	return tui.ModeInteractive, feeds.Empty{}, nil
}

// buildInteractiveFeed loads targets per --input kind and
// constructs a feeds.Interactive ready for the runner. v1.31+
// supports the same 8 kinds that the batch `scan` verb does
// (list:, nmap:, stdin, shodan:, censys:, fofa:, zoomeye:,
// onyphe:, internetdb:) via the shared parseInput dispatcher.
//
// stdin input note: when invoked with `--input stdin`, the
// dispatcher reads from os.Stdin. The TUI also takes its own
// keyboard input from os.Stdin once the alt screen mounts —
// these can't share. Operators wanting "stdin-as-input" should
// either pipe via `--feed -` (which reads NDJSON live) or use
// list:/dev/stdin. We keep the kind here for symmetry with
// `scan`, but it'll race the TUI input on a TTY.
func buildInteractiveFeed(ctx context.Context, inputKind string, defaultPort uint16, apiCredsFile string) (tui.Feed, error) {
	if inputKind == "" {
		return nil, errors.New("tui: --input: empty")
	}
	targets, err := parseInput(ctx, inputParseOpts{
		InputKind:    inputKind,
		DefaultPort:  int(defaultPort),
		APICredsFile: apiCredsFile,
	})
	if err != nil {
		return nil, fmt.Errorf("tui: --input %s: %w", inputKind, err)
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("tui: --input %s: no targets parsed", inputKind)
	}
	return feeds.Interactive{
		Targets: targets,
		Probe:   banner.Default().Probe,
	}, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
