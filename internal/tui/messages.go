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
