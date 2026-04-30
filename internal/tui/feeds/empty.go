//go:build !mini

// Package feeds implements the four TUI feed types (interactive,
// replay, stdin, watch). Each Feed satisfies tui.Feed and is
// selected at startup by the operator via CLI flags.
package feeds

import (
	"context"

	tea "github.com/charmbracelet/bubbletea"
)

// Empty is a no-op Feed used when the operator launches
// `elsereno tui` without specifying a mode flag. The TUI runs +
// the operator can navigate panes, but no events flow until
// they restart with --replay / --feed / --watch / interactive
// mode.
//
// Useful as a sanity check that the bubbletea program starts
// cleanly — and as the v1.29 chunk 2 default while replay /
// feed / watch land in chunks 3-5.
type Empty struct{}

// Name implements tui.Feed.
func (Empty) Name() string { return "empty" }

// Run implements tui.Feed. Blocks on ctx.Done() so the
// program lifecycle is correct, but emits no messages.
func (Empty) Run(ctx context.Context, _ func(tea.Msg)) error {
	<-ctx.Done()
	return nil
}
