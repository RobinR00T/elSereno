//go:build !mini

package tui

import (
	tea "github.com/charmbracelet/bubbletea"
)

// Update implements tea.Model. Folds incoming events into the
// Model + returns the next state + any commands.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.Width = msg.Width
		m.Height = msg.Height
		return m, nil

	case tea.KeyMsg:
		return m.handleKey(msg)

	case FindingMsg:
		m = m.AddFinding(msg.Finding)
		return m, nil

	case AuditMsg:
		m = m.AddAuditEvent(msg.Line)
		return m, nil

	case ScanProgressMsg:
		m = m.SetScanProgress(msg.Completed, msg.Total)
		return m, nil

	case FeedClosedMsg:
		// End-of-stream is informational, not fatal. The audit
		// feed picks up the closure as a synthetic line so the
		// operator sees what happened.
		line := "(feed closed: " + string(msg.Mode) + ")"
		if msg.Err != nil {
			line = "(feed closed with error: " + msg.Err.Error() + ")"
		}
		m = m.AddAuditEvent(line)
		return m, nil
	}
	return m, nil
}

// handleKey routes keypresses based on the focused pane. Common
// keys (q to quit, Tab to cycle focus) are pane-agnostic.
func (m Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "ctrl+c":
		m.Quitting = true
		return m, tea.Quit
	case "tab":
		return m.CycleFocus(false), nil
	case "shift+tab":
		return m.CycleFocus(true), nil
	case "j", "down":
		if m.FocusedPane == PaneFindings {
			m = m.MoveCursor(1)
		}
		return m, nil
	case "k", "up":
		if m.FocusedPane == PaneFindings {
			m = m.MoveCursor(-1)
		}
		return m, nil
	case "g", "home":
		if m.FocusedPane == PaneFindings {
			m.Cursor = 0
		}
		return m, nil
	case "G", "end":
		if m.FocusedPane == PaneFindings && len(m.Findings) > 0 {
			m.Cursor = len(m.Findings) - 1
		}
		return m, nil
	}
	return m, nil
}
