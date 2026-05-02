//go:build offensive

package main

import (
	"context"
	"fmt"
	"strings"

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
func newProxyReplayCmd() *cobra.Command {
	var hexLimit int
	var dirFilter string
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
(default 32; 0 = full).`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]

			hdr, err := replay.SeekHeader(path)
			if err != nil {
				return fail(core.ExitOSErr, fmt.Errorf("replay: %w", err))
			}
			cmd.Printf("# capture %s\n", path)
			cmd.Printf("# protocol  %s\n", hdr.Protocol)
			cmd.Printf("# target    %s\n", hdr.Target)
			cmd.Printf("# started   %s\n", hdr.StartedAt.UTC().Format("2006-01-02T15:04:05.999999Z07:00"))
			cmd.Println()

			wantClient, wantUpstream := parseDirFilter(dirFilter)
			ctx := cmd.Context()
			err = replay.Replay(ctx, path, func(ev replay.ChunkEvent) error {
				if ev.Dir == replay.DirClientToUpstream && !wantClient {
					return nil
				}
				if ev.Dir == replay.DirUpstreamToClient && !wantUpstream {
					return nil
				}
				cmd.Println(formatChunk(ev, hexLimit))
				return nil
			})
			if err != nil {
				return fail(core.ExitError, fmt.Errorf("replay: %w", err))
			}
			return nil
		},
	}
	cmd.Flags().IntVar(&hexLimit, "hex-limit", 32, "truncate hex preview at N bytes (0 = full)")
	cmd.Flags().StringVar(&dirFilter, "dir", "both", "direction: client | upstream | both")
	return cmd
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
