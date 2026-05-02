//go:build !mini

package feeds

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	tea "github.com/charmbracelet/bubbletea"
)

// Replay reads an ndjson:v1 capture file from disk and emits one
// tui.FindingMsg per record. Pairs with `elsereno scan
// --output-format ndjson > file.ndjson`; the operator can then
// drive the TUI from that capture for triage / demos / training
// without re-running the scan.
//
// Replay honours a Rate (lines per second) for slow-motion
// playback. Rate <= 0 → as fast as possible. Useful for demos
// where the scan finished in 200 ms but the audience needs to
// see findings appear.
//
// On parse error, the bad line is converted into a synthetic
// AuditMsg ("ndjson: skipped malformed line N: …") rather than
// terminating the feed — a single corrupted entry shouldn't kill
// a long capture. The first I/O error (read failure, EOF
// excepted) terminates the feed and is returned via Run.
type Replay struct {
	// Path is the on-disk file. Required.
	Path string
	// Rate is the playback rate in lines per second. 0 (the
	// default) plays as fast as the goroutine schedules.
	Rate float64
}

// Name implements tui.Feed.
func (r Replay) Name() string {
	return "replay " + r.Path
}

// Run implements tui.Feed. Opens Path, streams lines, converts
// each to a tui.FindingMsg + emits.
func (r Replay) Run(ctx context.Context, emit func(tea.Msg)) error {
	if r.Path == "" {
		return errors.New("replay: empty Path")
	}
	f, err := os.Open(r.Path) // #nosec G304 -- operator-supplied --replay path is intended.
	if err != nil {
		return fmt.Errorf("replay: open %s: %w", r.Path, err)
	}
	defer func() { _ = f.Close() }()

	return r.stream(ctx, f, emit)
}

// stream is split out so tests drive an io.Reader directly.
func (r Replay) stream(ctx context.Context, src io.Reader, emit func(tea.Msg)) error {
	return streamNDJSON(ctx, src, emit, paceFromRate(r.Rate))
}
