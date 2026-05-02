//go:build !mini

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"local/elsereno/internal/core"
	"local/elsereno/internal/inputs/list"
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
	var replayPath string
	var feedFlag string
	var watchURL string
	var watchBearer string
	var inputKind string
	var defaultPort uint16
	cmd := &cobra.Command{
		Use:   "tui",
		Short: "Interactive terminal UI (default + offensive builds; not in mini)",
		Long: `Open the interactive ElSereno TUI. Five modes:

  - interactive (default): empty panes; useful sanity check.
  - --input list:FILE: scan from inside the TUI (v1.30+).
    Loads targets from FILE + drives a Scanner whose findings
    populate the panes live.
  - --replay FILE.ndjson: review a pre-recorded NDJSON capture.
  - --feed -: consume NDJSON from stdin (pairs with the batch
    scan verb's --output-format ndjson).
  - --watch URL --bearer TOKEN: subscribe to a remote
    dashboard's SSE feed (read-only).

Tab cycles focus between panes; j/k navigate the findings
table; q quits.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			mode, feed, err := pickFeed(cmd.Context(), pickFeedArgs{
				replayPath:  replayPath,
				feedFlag:    feedFlag,
				watchURL:    watchURL,
				watchBearer: watchBearer,
				inputKind:   inputKind,
				defaultPort: defaultPort,
			})
			if err != nil {
				return fail(core.ExitUsage, err)
			}
			ctx := cmd.Context()
			if err := tui.Run(ctx, mode, feed, os.Stdout, os.Stdin); err != nil {
				return fail(core.ExitSoftware, fmt.Errorf("tui: %w", err))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&inputKind, "input", "",
		"v1.30+: scan from inside the TUI. Format `list:<path>` (other input kinds — nmap:, shodan:, … — coming in later cycles)")
	cmd.Flags().Uint16Var(&defaultPort, "default-port", 0,
		"v1.30+: default port for --input list entries that omit one (host-only lines)")
	cmd.Flags().StringVar(&replayPath, "replay", "",
		"NDJSON capture file to replay (mutually exclusive with --feed and --watch)")
	cmd.Flags().StringVar(&feedFlag, "feed", "",
		"NDJSON feed source (only `-` for stdin is supported; use --replay for files)")
	cmd.Flags().StringVar(&watchURL, "watch", "",
		"dashboard SSE URL to consume (e.g. https://host:8443/api/v1/stream)")
	cmd.Flags().StringVar(&watchBearer, "bearer", "",
		"Bearer token for --watch URL (required for non-loopback targets)")
	return cmd
}

// pickFeedArgs bundles the CLI flags pickFeed consumes so its
// signature stays under the linter's argument-count limit. The
// struct is private to cmd_tui.go.
type pickFeedArgs struct {
	replayPath  string
	feedFlag    string
	watchURL    string
	watchBearer string
	inputKind   string
	defaultPort uint16
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
		return tui.ModeReplay, feeds.Replay{Path: a.replayPath}, nil
	case hasFeed:
		// Only `-` is supported (stdin). `--feed FILE` is
		// redundant with `--replay FILE`; rejecting it here
		// keeps the two flags' intent distinct (replay = file
		// playback; feed = live producer).
		if a.feedFlag != "-" {
			return "", nil, fmt.Errorf("tui: --feed accepts only `-` (stdin); use --replay for files (got %q)", a.feedFlag)
		}
		return tui.ModeFeed, feeds.Stdin{In: os.Stdin}, nil
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
		feed, err := buildInteractiveFeed(ctx, a.inputKind, a.defaultPort)
		if err != nil {
			return "", nil, err
		}
		return tui.ModeInteractive, feed, nil
	}
	// Default: interactive mode with the empty feed.
	return tui.ModeInteractive, feeds.Empty{}, nil
}

// buildInteractiveFeed loads targets per --input kind and
// constructs a feeds.Interactive ready for the runner. v1.30
// chunk 3 supports `list:FILE` only; nmap / shodan / censys /
// fofa / zoomeye / onyphe / internetdb arrive in later cycles
// (each pulls in extra deps + provider creds plumbing — out of
// scope for the chunk that wires the live-scan path).
func buildInteractiveFeed(ctx context.Context, inputKind string, defaultPort uint16) (tui.Feed, error) {
	const prefix = "list:"
	if !strings.HasPrefix(inputKind, prefix) {
		return nil, fmt.Errorf("tui: --input %q: only `list:<path>` is supported in v1.30; pipe other inputs via `elsereno scan --output-format ndjson | elsereno tui --feed -`", inputKind)
	}
	path := strings.TrimPrefix(inputKind, prefix)
	if path == "" {
		return nil, errors.New("tui: --input list: empty path")
	}
	f, err := os.Open(path) // #nosec G304 -- operator-supplied --input list:<path> is intended.
	if err != nil {
		return nil, fmt.Errorf("tui: --input list:%s: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	targets, err := list.Parse(ctx, f, list.ParseOptions{DefaultPort: core.Port(defaultPort)})
	if err != nil {
		return nil, fmt.Errorf("tui: --input list:%s: %w", path, err)
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("tui: --input list:%s: no targets parsed", path)
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
