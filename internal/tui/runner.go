//go:build !mini

package tui

import (
	"context"
	"fmt"
	"io"

	tea "github.com/charmbracelet/bubbletea"
)

// Feed produces tea.Msg values for the bubbletea program (one
// per event from the underlying source). Implementations:
//
//   - feeds.Replay  reads an NDJSON file from disk + emits
//     FindingMsg per line.
//   - feeds.Stdin   reads NDJSON from stdin live.
//   - feeds.Watch   subscribes to the dashboard's SSE
//     broadcaster.
//   - feeds.Interactive starts a scanner.Scanner from inside
//     the TUI + funnels its outputs to messages.
//
// The Feed runs in its own goroutine; tea.Program orchestrates
// the message loop.
type Feed interface {
	// Name is a human-readable identifier (e.g. "replay
	// /tmp/x.ndjson"). Used in error reports.
	Name() string
	// Run drives the feed. emit is a callback that pushes a
	// tea.Msg onto the program. Returns when the feed is
	// exhausted or ctx is cancelled.
	Run(ctx context.Context, emit func(tea.Msg)) error
}

// Run starts the bubbletea program with the supplied Feed +
// initial mode. Blocks until the user quits or ctx cancels.
//
// out / in are the terminal handles (typically os.Stdout +
// os.Stdin); injectable so tests can drive the TUI through a
// teatest harness.
func Run(ctx context.Context, mode Mode, feed Feed, out io.Writer, in io.Reader) error {
	model := NewModel(mode)
	prog := tea.NewProgram(
		model,
		tea.WithContext(ctx),
		tea.WithOutput(out),
		tea.WithInput(in),
		tea.WithAltScreen(),
	)

	// Run the feed in a goroutine; emit pushes into the program.
	feedDone := make(chan error, 1)
	go func() {
		emit := func(msg tea.Msg) { prog.Send(msg) }
		err := feed.Run(ctx, emit)
		// Notify the Model so the UI can record the closure.
		prog.Send(FeedClosedMsg{Mode: mode, Err: err})
		feedDone <- err
	}()

	if _, err := prog.Run(); err != nil {
		return fmt.Errorf("tui: program: %w", err)
	}
	// Drain the feed goroutine so we don't leak it.
	<-feedDone
	return nil
}
