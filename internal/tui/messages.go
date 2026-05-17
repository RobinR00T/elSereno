//go:build !mini

package tui

import (
	"local/elsereno/internal/core"
)

// FindingMsg is the bubbletea message dispatched when a new
// Finding arrives from any feed (interactive scan, replay,
// stdin, SSE). Update folds it into m.Findings + m.TriageCounts.
type FindingMsg struct {
	Finding core.Finding
}

// AuditMsg is the bubbletea message dispatched when a new audit
// event arrives. The line is already rendered (typically by the
// feed reader) so View can drop it straight into the audit
// panel.
type AuditMsg struct {
	Line string
}

// ScanProgressMsg is the bubbletea message dispatched as the
// scanner advances. total=0 ends the scan; non-zero updates the
// bar.
type ScanProgressMsg struct {
	Completed int64
	Total     int64
}

// FeedClosedMsg signals end-of-stream. The TUI keeps running so
// the operator can review the final state; Quit on `q` as
// usual.
type FeedClosedMsg struct {
	Mode Mode
	Err  error
}

// ReplayStatusMsg (v2.51+) is emitted periodically by the
// Replay feed so the TUI can render playback progress in the
// audit pane. Useful for long captures where the operator
// wants to know "am I 10% or 90% through?".
//
// The feed emits one ReplayStatusMsg every N lines (configured
// via Replay.StatusEvery) — typically every 100 lines.
type ReplayStatusMsg struct {
	// Path of the capture file being replayed.
	Path string
	// LineCount is the number of lines emitted so far.
	LineCount int64
	// Rate is the configured playback rate (lines/sec; 0 =
	// uncapped). Surfaced for the operator's reference.
	Rate float64
}

// ReplayController (v2.53+) is the minimum surface the TUI
// key handler needs to drive runtime playback control. The
// concrete impl lives in internal/tui/feeds.ReplayControl;
// using an interface here breaks the would-be cycle (tui →
// feeds → tui).
type ReplayController interface {
	// TogglePause flips paused state. Returns the new state.
	TogglePause() bool
	// Paused reports whether playback is paused.
	Paused() bool
	// HalveRate / DoubleRate adjust the playback rate.
	HalveRate()
	DoubleRate()
	// Rate returns the current rate (lines/sec; 0 = uncapped).
	Rate() float64
}
