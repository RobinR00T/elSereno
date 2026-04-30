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
// terminal UI. v1.29 chunk 2 ships the Model/View/Update +
// the empty-feed default; chunks 3-5 add replay / feed / watch
// modes (each its own --replay / --feed / --watch flag).
//
// The TUI is purely additive: every existing batch verb (scan,
// write, exploit, harvest, dial, audit, proxy listen, …)
// keeps its current behaviour. The TUI is opt-in via this
// dedicated verb.
//
// Build tag: `//go:build !mini`. The mini variant gets a stub
// in cmd_tui_mini.go that prints "TUI not available in mini
// build" and exits with EX_UNAVAILABLE (75).
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
		"NDJSON capture to replay (mutually exclusive with --feed and --watch)")
	cmd.Flags().StringVar(&feedFlag, "feed", "",
		"NDJSON feed source (`-` for stdin; arrives in v1.29 chunk 4)")
	cmd.Flags().StringVar(&watchURL, "watch", "",
		"dashboard SSE URL to consume (arrives in v1.29 chunk 5)")
	cmd.Flags().StringVar(&watchBearer, "bearer", "",
		"Bearer token for --watch URL")
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
		return tui.ModeReplay, nil, errors.New("tui: --replay arrives in v1.29 chunk 3 (chunk 2 ships interactive scaffolding only)")
	case hasFeed:
		return tui.ModeFeed, nil, errors.New("tui: --feed arrives in v1.29 chunk 4 (chunk 2 ships interactive scaffolding only)")
	case hasWatch:
		_ = watchBearer
		return tui.ModeWatch, nil, errors.New("tui: --watch arrives in v1.29 chunk 5 (chunk 2 ships interactive scaffolding only)")
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
