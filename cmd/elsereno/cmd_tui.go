//go:build !mini

package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"local/elsereno/internal/core"
	"local/elsereno/internal/tui"
	"local/elsereno/internal/tui/feeds"
)

// newTUICmd registers `elsereno tui` — the interactive
// terminal UI. Four modes selected by flag:
//
//   - (no flag)        interactive — opens the panes with an
//     empty feed; future enhancement will spin
//     up a Scanner from inside the TUI.
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
	cmd := &cobra.Command{
		Use:   "tui",
		Short: "Interactive terminal UI (default + offensive builds; not in mini)",
		Long: `Open the interactive ElSereno TUI. Four modes:

  - interactive (default): scan + triage + audit feed driven
    from inside the TUI.
  - --replay FILE.ndjson: review a pre-recorded NDJSON capture.
  - --feed -: consume NDJSON from stdin (pairs with the batch
    scan verb's --output-format ndjson).
  - --watch URL --bearer TOKEN: subscribe to a remote
    dashboard's SSE feed (read-only).

Tab cycles focus between panes; j/k navigate the findings
table; q quits.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			mode, feed, err := pickFeed(replayPath, feedFlag, watchURL, watchBearer)
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

// pickFeed maps the CLI flags to a tui.Feed + Mode. Mutual
// exclusion is enforced — each --replay / --feed / --watch
// excludes the others. No flag → interactive mode (currently
// emits no events until the live-scan path lands; the empty
// feed lets operators verify the program runs).
func pickFeed(replayPath, feedFlag, watchURL, watchBearer string) (tui.Mode, tui.Feed, error) {
	hasReplay := replayPath != ""
	hasFeed := feedFlag != ""
	hasWatch := watchURL != ""
	if (boolToInt(hasReplay) + boolToInt(hasFeed) + boolToInt(hasWatch)) > 1 {
		return "", nil, errors.New("tui: --replay, --feed, --watch are mutually exclusive")
	}
	switch {
	case hasReplay:
		// Pre-flight stat. We don't open here — the feed
		// goroutine does that — but a missing file is the
		// common operator typo, and surfacing it before the
		// alt screen takes over saves them from a confusing
		// "feed closed with error" line on a still-blank TUI.
		if info, statErr := os.Stat(replayPath); statErr != nil {
			return "", nil, fmt.Errorf("tui: --replay: %w", statErr)
		} else if info.IsDir() {
			return "", nil, fmt.Errorf("tui: --replay: %s is a directory", replayPath)
		}
		return tui.ModeReplay, feeds.Replay{Path: replayPath}, nil
	case hasFeed:
		// Only `-` is supported (stdin). `--feed FILE` is
		// redundant with `--replay FILE`; rejecting it here
		// keeps the two flags' intent distinct (replay = file
		// playback; feed = live producer).
		if feedFlag != "-" {
			return "", nil, fmt.Errorf("tui: --feed accepts only `-` (stdin); use --replay for files (got %q)", feedFlag)
		}
		return tui.ModeFeed, feeds.Stdin{In: os.Stdin}, nil
	case hasWatch:
		// --bearer is required for any non-loopback target;
		// `serve` rejects unauthenticated stream subscribes.
		// We don't enforce here (loopback is permitted); the
		// runtime will surface 401 fast via authError.
		return tui.ModeWatch, feeds.Watch{
			URL:    watchURL,
			Bearer: watchBearer,
		}, nil
	}
	// Default: interactive mode with the empty feed (chunk 2
	// scaffolding). Live scan-from-TUI is a later enrichment.
	return tui.ModeInteractive, feeds.Empty{}, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
