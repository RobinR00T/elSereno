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
	// v1.30 chunk 4: while editing a filter, every key feeds the
	// draft until Enter / Esc. Capture this BEFORE the global
	// shortcuts so `q` inside a filter typing session doesn't
	// quit the program.
	if m.FilterEditing {
		return m.handleFilterKey(msg)
	}
	key := msg.String()
	switch key {
	case "q", "ctrl+c":
		m.Quitting = true
		return m, tea.Quit
	case "tab":
		return m.CycleFocus(false), nil
	case "shift+tab":
		return m.CycleFocus(true), nil
	case "/":
		// v1.30 chunk 4: enter filter-edit mode for the audit
		// pane. Only meaningful when the audit pane is focused;
		// elsewhere it's a no-op so a misclick on `/` doesn't
		// surprise the operator.
		if m.FocusedPane == PaneAudit {
			m.FilterEditing = true
			m.FilterDraft = m.AuditFilter
		}
		return m, nil
	case "esc":
		// Outside filter-edit mode, Esc clears any active
		// filter. Inside filter-edit (handled above) it cancels
		// the draft.
		m.AuditFilter = ""
		return m, nil
	}
	return m.handleNavKey(key), nil
}

// handleNavKey routes the j/k/g/G + arrow + home/end navigation
// keys. Pulled out from handleKey so each function stays under
// the linter's cyclomatic-complexity ceiling. Pane-aware: nav
// keys only act when the findings pane is focused.
func (m Model) handleNavKey(key string) Model {
	if m.FocusedPane != PaneFindings {
		return m
	}
	switch key {
	case "j", "down":
		return m.MoveCursor(1)
	case "k", "up":
		return m.MoveCursor(-1)
	case "g", "home":
		m.Cursor = 0
	case "G", "end":
		if len(m.Findings) > 0 {
			m.Cursor = len(m.Findings) - 1
		}
	}
	return m
}

// handleFilterKey routes keypresses while the operator is
// typing into the audit-pane filter. Enter commits the draft;
// Esc cancels (restores the previous filter); Backspace
// deletes one rune from the tail; printable keys append.
// tea.KeyType has dozens of named keys; we only care about the
// editor-meaningful subset and treat the rest as no-ops via
// the default branch — hence the exhaustive lint suppression.
//
//nolint:exhaustive // see comment above.
func (m Model) handleFilterKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyEnter:
		m.AuditFilter = m.FilterDraft
		m.FilterEditing = false
		m.FilterDraft = ""
	case tea.KeyEsc:
		m.FilterEditing = false
		m.FilterDraft = ""
	case tea.KeyBackspace:
		if r := []rune(m.FilterDraft); len(r) > 0 {
			m.FilterDraft = string(r[:len(r)-1])
		}
	case tea.KeyRunes:
		m.FilterDraft += string(msg.Runes)
	case tea.KeySpace:
		m.FilterDraft += " "
	default:
		// Other keys (arrows, function keys, ctrl-combos other
		// than ctrl+c which is handled before we get here) are
		// no-ops while editing.
	}
	return m, nil
}
