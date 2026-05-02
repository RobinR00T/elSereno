//go:build !mini

package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

// TestFilteredAuditEvents_NoFilter — empty filter returns the
// full slice (identity).
func TestFilteredAuditEvents_NoFilter(t *testing.T) {
	m := NewModel(ModeInteractive)
	m = m.AddAuditEvent("vault unlocked")
	m = m.AddAuditEvent("scan started")
	got := m.FilteredAuditEvents()
	if len(got) != 2 {
		t.Errorf("len = %d, want 2", len(got))
	}
}

// TestFilteredAuditEvents_CaseInsensitive — filter matches
// regardless of case so `/vault` finds both "vault" and "Vault".
func TestFilteredAuditEvents_CaseInsensitive(t *testing.T) {
	m := NewModel(ModeInteractive)
	m = m.AddAuditEvent("Vault unlocked")
	m = m.AddAuditEvent("scan started")
	m = m.AddAuditEvent("vault locked")
	m.AuditFilter = "VAULT"
	got := m.FilteredAuditEvents()
	if len(got) != 2 {
		t.Errorf("len = %d, want 2", len(got))
	}
	for _, line := range got {
		if !strings.Contains(strings.ToLower(line), "vault") {
			t.Errorf("non-matching line in result: %q", line)
		}
	}
}

// TestFilteredAuditEvents_NoMatches — filter that matches
// nothing returns an empty (but non-nil) slice.
func TestFilteredAuditEvents_NoMatches(t *testing.T) {
	m := NewModel(ModeInteractive)
	m = m.AddAuditEvent("scan started")
	m.AuditFilter = "bogus"
	got := m.FilteredAuditEvents()
	if got == nil {
		t.Errorf("nil; want empty slice")
	}
	if len(got) != 0 {
		t.Errorf("len = %d, want 0", len(got))
	}
}

// TestFilterEdit_EnterCommits — pressing `/` on the audit pane
// enters edit mode; typed runes accumulate into FilterDraft;
// Enter commits to AuditFilter.
func TestFilterEdit_EnterCommits(t *testing.T) {
	m := NewModel(ModeInteractive)
	m.FocusedPane = PaneAudit

	mm, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("/")})
	got := asTUIModel(t, mm)
	if !got.FilterEditing {
		t.Fatalf("FilterEditing=false after `/`")
	}

	// Type "vault" rune by rune.
	for _, r := range "vault" {
		mm, _ = got.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
		got = asTUIModel(t, mm)
	}
	if got.FilterDraft != "vault" {
		t.Errorf("FilterDraft = %q, want %q", got.FilterDraft, "vault")
	}

	// Enter commits.
	mm, _ = got.Update(tea.KeyMsg{Type: tea.KeyEnter})
	got = asTUIModel(t, mm)
	if got.FilterEditing {
		t.Errorf("FilterEditing=true after Enter; want committed")
	}
	if got.AuditFilter != "vault" {
		t.Errorf("AuditFilter = %q, want %q", got.AuditFilter, "vault")
	}
	if got.FilterDraft != "" {
		t.Errorf("FilterDraft not cleared: %q", got.FilterDraft)
	}
}

// TestFilterEdit_EscCancels — Esc inside edit mode discards
// the draft + restores the previous AuditFilter (here empty).
func TestFilterEdit_EscCancels(t *testing.T) {
	m := NewModel(ModeInteractive)
	m.FocusedPane = PaneAudit
	m.AuditFilter = "old"

	mm, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("/")})
	got := asTUIModel(t, mm)
	mm, _ = got.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("x")})
	got = asTUIModel(t, mm)
	mm, _ = got.Update(tea.KeyMsg{Type: tea.KeyEsc})
	got = asTUIModel(t, mm)
	if got.FilterEditing {
		t.Errorf("FilterEditing=true after Esc")
	}
	if got.AuditFilter != "old" {
		t.Errorf("AuditFilter = %q, want preserved %q", got.AuditFilter, "old")
	}
}

// TestFilterEdit_BackspaceDeletes — Backspace pops one rune
// from the draft.
func TestFilterEdit_BackspaceDeletes(t *testing.T) {
	m := NewModel(ModeInteractive)
	m.FocusedPane = PaneAudit
	m.FilterEditing = true
	m.FilterDraft = "vault"

	mm, _ := m.Update(tea.KeyMsg{Type: tea.KeyBackspace})
	got := asTUIModel(t, mm)
	if got.FilterDraft != "vaul" {
		t.Errorf("FilterDraft = %q, want %q", got.FilterDraft, "vaul")
	}
}

// TestFilterEdit_DoesNotQuit — `q` while editing must NOT
// trigger tea.Quit; it should accumulate as a draft rune.
func TestFilterEdit_DoesNotQuit(t *testing.T) {
	m := NewModel(ModeInteractive)
	m.FilterEditing = true
	mm, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")})
	got := asTUIModel(t, mm)
	if got.Quitting {
		t.Errorf("Quitting=true while filter editing; should accumulate draft")
	}
	if cmd != nil {
		t.Errorf("got cmd %v while filter editing; should be nil", cmd)
	}
	if got.FilterDraft != "q" {
		t.Errorf("FilterDraft = %q, want %q", got.FilterDraft, "q")
	}
}

// TestEsc_ClearsActiveFilter — Esc outside edit mode clears the
// committed filter.
func TestEsc_ClearsActiveFilter(t *testing.T) {
	m := NewModel(ModeInteractive)
	m.AuditFilter = "vault"
	mm, _ := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	got := asTUIModel(t, mm)
	if got.AuditFilter != "" {
		t.Errorf("AuditFilter = %q, want cleared", got.AuditFilter)
	}
}

// TestSlash_OnlyOnAuditPane — `/` outside the audit pane is a
// no-op so a misclick doesn't activate filter edit somewhere
// it doesn't make sense.
func TestSlash_OnlyOnAuditPane(t *testing.T) {
	m := NewModel(ModeInteractive)
	m.FocusedPane = PaneFindings
	mm, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("/")})
	got := asTUIModel(t, mm)
	if got.FilterEditing {
		t.Errorf("FilterEditing=true on non-audit pane")
	}
}

// asTUIModel mirrors update_test.go's asModel (the test files
// are in the same package; pulled out here so filter_test stays
// self-contained).
func asTUIModel(t *testing.T, mm tea.Model) Model {
	t.Helper()
	m, ok := mm.(Model)
	if !ok {
		t.Fatalf("Update returned %T, not Model", mm)
	}
	return m
}
