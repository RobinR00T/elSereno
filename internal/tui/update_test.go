//go:build !mini

package tui

import (
	"errors"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"local/elsereno/internal/core"
)

// asModel unwraps the tea.Model returned by Update back to our
// concrete type. Update returns the interface so the test has to
// type-assert; pulled into a helper so each call site is one line.
func asModel(t *testing.T, mm tea.Model) Model {
	t.Helper()
	m, ok := mm.(Model)
	if !ok {
		t.Fatalf("Update returned %T, not Model", mm)
	}
	return m
}

// TestUpdateWindowSizeMsg pins the dimension fan-in.
func TestUpdateWindowSizeMsg(t *testing.T) {
	m := NewModel(ModeInteractive)
	mm, cmd := m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	if cmd != nil {
		t.Errorf("WindowSizeMsg returned a cmd; expected nil")
	}
	got := asModel(t, mm)
	if got.Width != 120 || got.Height != 40 {
		t.Errorf("size = (%d, %d), want (120, 40)", got.Width, got.Height)
	}
}

// TestUpdateFindingMsgFolds confirms the message-to-state path.
func TestUpdateFindingMsgFolds(t *testing.T) {
	m := NewModel(ModeInteractive)
	mm, _ := m.Update(FindingMsg{Finding: core.Finding{Score: 95}})
	got := asModel(t, mm)
	if got.TriageCounts[SeverityCritical] != 1 {
		t.Errorf("critical count = %d, want 1 (counts: %v)",
			got.TriageCounts[SeverityCritical], got.TriageCounts)
	}
}

// TestUpdateAuditMsgFolds confirms the audit-feed wiring.
func TestUpdateAuditMsgFolds(t *testing.T) {
	m := NewModel(ModeInteractive)
	mm, _ := m.Update(AuditMsg{Line: "audit: vault unlocked"})
	got := asModel(t, mm)
	if len(got.AuditEvents) != 1 || got.AuditEvents[0] != "audit: vault unlocked" {
		t.Errorf("audit events: %v", got.AuditEvents)
	}
}

// TestUpdateScanProgressMsg routes ScanProgressMsg through the
// state mutation.
func TestUpdateScanProgressMsg(t *testing.T) {
	m := NewModel(ModeInteractive)
	mm, _ := m.Update(ScanProgressMsg{Completed: 25, Total: 100})
	got := asModel(t, mm)
	if !got.ScanRunning || got.ScanProgress != 0.25 {
		t.Errorf("scan progress: running=%v progress=%v",
			got.ScanRunning, got.ScanProgress)
	}
}

// TestUpdateFeedClosedMsgRendersLine pins the synthetic audit
// entry — operator-visible signal that the feed terminated.
func TestUpdateFeedClosedMsgRendersLine(t *testing.T) {
	m := NewModel(ModeReplay)
	mm, _ := m.Update(FeedClosedMsg{Mode: ModeReplay, Err: nil})
	got := asModel(t, mm)
	if len(got.AuditEvents) != 1 {
		t.Fatalf("audit events: %v", got.AuditEvents)
	}
	if got.AuditEvents[0] != "(feed closed: replay)" {
		t.Errorf("close line: %q", got.AuditEvents[0])
	}

	mm, _ = m.Update(FeedClosedMsg{Mode: ModeReplay, Err: errors.New("EOF")})
	got = asModel(t, mm)
	if len(got.AuditEvents) != 1 {
		t.Fatalf("err audit events: %v", got.AuditEvents)
	}
	if got.AuditEvents[0] != "(feed closed with error: EOF)" {
		t.Errorf("err close line: %q", got.AuditEvents[0])
	}
}

// TestHandleKeyQuit pins the q/ctrl+c bindings — the top-level
// way to leave the TUI cleanly.
func TestHandleKeyQuit(t *testing.T) {
	for _, key := range []string{"q", "ctrl+c"} {
		m := NewModel(ModeInteractive)
		mm, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(key)})
		if key == "ctrl+c" {
			// ctrl+c needs the Type variant.
			mm, cmd = m.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
		}
		got := asModel(t, mm)
		if !got.Quitting {
			t.Errorf("key %q: Quitting=false", key)
		}
		if cmd == nil {
			t.Errorf("key %q: cmd is nil; expected tea.Quit", key)
		}
	}
}

// TestHandleKeyTab walks Tab + Shift+Tab through the cycle.
func TestHandleKeyTab(t *testing.T) {
	m := NewModel(ModeInteractive)
	mm, _ := m.Update(tea.KeyMsg{Type: tea.KeyTab})
	got := asModel(t, mm)
	if got.FocusedPane != PaneTriage {
		t.Errorf("tab: FocusedPane=%v, want PaneTriage", got.FocusedPane)
	}
	mm, _ = got.Update(tea.KeyMsg{Type: tea.KeyShiftTab})
	got = asModel(t, mm)
	if got.FocusedPane != PaneFindings {
		t.Errorf("shift+tab: FocusedPane=%v, want PaneFindings", got.FocusedPane)
	}
}

// TestHandleKeyJKOnFindings drives j/k against the findings pane.
// On non-findings panes the keys are pane-agnostic noops.
func TestHandleKeyJKOnFindings(t *testing.T) {
	m := NewModel(ModeInteractive)
	m = m.AddFinding(core.Finding{Score: 50})
	m = m.AddFinding(core.Finding{Score: 50})
	m = m.AddFinding(core.Finding{Score: 50})
	if m.FocusedPane != PaneFindings {
		t.Fatalf("setup: FocusedPane=%v, want PaneFindings", m.FocusedPane)
	}

	mm, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("j")})
	got := asModel(t, mm)
	if got.Cursor != 1 {
		t.Errorf("j: Cursor=%d, want 1", got.Cursor)
	}

	mm, _ = got.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("G")})
	got = asModel(t, mm)
	if got.Cursor != 2 {
		t.Errorf("G: Cursor=%d, want 2", got.Cursor)
	}

	mm, _ = got.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("g")})
	got = asModel(t, mm)
	if got.Cursor != 0 {
		t.Errorf("g: Cursor=%d, want 0", got.Cursor)
	}

	// Switch focus and confirm j/k stops moving Cursor.
	got = got.CycleFocus(false) // PaneTriage
	mm, _ = got.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("j")})
	got = asModel(t, mm)
	if got.Cursor != 0 {
		t.Errorf("j on PaneTriage: Cursor=%d, want still 0", got.Cursor)
	}
}
