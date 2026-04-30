//go:build !mini

package tui

import (
	"testing"
	"time"

	"local/elsereno/internal/core"
)

// TestNewModel pins the Mode + the rolling-window defaults. The
// caps (200 findings, 100 audit events) are public contract — a
// bump here means a doc update.
func TestNewModel(t *testing.T) {
	m := NewModel(ModeReplay)
	if m.ModeName != ModeReplay {
		t.Fatalf("Mode = %q, want %q", m.ModeName, ModeReplay)
	}
	if m.MaxFindings != 200 {
		t.Errorf("MaxFindings = %d, want 200", m.MaxFindings)
	}
	if m.MaxAuditEvents != 100 {
		t.Errorf("MaxAuditEvents = %d, want 100", m.MaxAuditEvents)
	}
	if m.FocusedPane != PaneFindings {
		t.Errorf("FocusedPane = %v, want PaneFindings", m.FocusedPane)
	}
	if m.Now == nil {
		t.Errorf("Now is nil — should default to time.Now")
	}
	// Init must return a nil cmd; feeds drive the loop, not a tick.
	if cmd := m.Init(); cmd != nil {
		t.Errorf("Init() returned a cmd; expected nil")
	}
}

// TestAddFindingBucketing pins the score → severity mapping (the
// bands mirror ADR-006). Regressing a band means the dashboard
// triage colours will diverge from the TUI's, so this test
// gates all rule changes.
func TestAddFindingBucketing(t *testing.T) {
	cases := []struct {
		score int
		want  Severity
	}{
		{99, SeverityCritical},
		{90, SeverityCritical},
		{89, SeverityHigh},
		{70, SeverityHigh},
		{69, SeverityMedium},
		{50, SeverityMedium},
		{49, SeverityLow},
		{25, SeverityLow},
		{24, SeverityInfo},
		{0, SeverityInfo},
	}
	for _, c := range cases {
		m := NewModel(ModeInteractive)
		m = m.AddFinding(core.Finding{Score: c.score})
		if got := m.TriageCounts[c.want]; got != 1 {
			t.Errorf("score %d → bucket %q count = %d, want 1 (full counts: %v)",
				c.score, c.want, got, m.TriageCounts)
		}
	}
}

// TestAddFindingRollingWindow pins the cap-then-trim behaviour.
// Cursor must stay in-bounds when the window slides.
func TestAddFindingRollingWindow(t *testing.T) {
	m := NewModel(ModeInteractive)
	m.MaxFindings = 3
	m.Cursor = 2 // Pretend the user is on the last row.

	for i := 0; i < 5; i++ {
		m = m.AddFinding(core.Finding{Score: 50})
	}
	if got := len(m.Findings); got != 3 {
		t.Fatalf("len(Findings) = %d, want 3", got)
	}
	if m.Cursor < 0 || m.Cursor >= len(m.Findings) {
		t.Errorf("Cursor=%d out of bounds (len=%d)", m.Cursor, len(m.Findings))
	}
}

// TestCycleFocus walks the four panes in both directions to
// confirm wrap behaviour matches Tab / Shift+Tab semantics.
func TestCycleFocus(t *testing.T) {
	m := NewModel(ModeInteractive)
	want := []Pane{PaneTriage, PaneAudit, PaneScan, PaneFindings}
	for i, p := range want {
		m = m.CycleFocus(false)
		if m.FocusedPane != p {
			t.Errorf("forward cycle %d: FocusedPane=%v, want %v", i, m.FocusedPane, p)
		}
	}
	wantRev := []Pane{PaneScan, PaneAudit, PaneTriage, PaneFindings}
	for i, p := range wantRev {
		m = m.CycleFocus(true)
		if m.FocusedPane != p {
			t.Errorf("reverse cycle %d: FocusedPane=%v, want %v", i, m.FocusedPane, p)
		}
	}
}

// TestMoveCursorClamps ensures j/k can't drive Cursor past the
// last finding nor below 0 — the View would index out of range.
func TestMoveCursorClamps(t *testing.T) {
	m := NewModel(ModeInteractive)
	m = m.AddFinding(core.Finding{Score: 50})
	m = m.AddFinding(core.Finding{Score: 50})

	m = m.MoveCursor(-5)
	if m.Cursor != 0 {
		t.Errorf("after -5 from 0: Cursor=%d, want 0", m.Cursor)
	}
	m = m.MoveCursor(99)
	if m.Cursor != 1 {
		t.Errorf("after +99 from 0 with 2 findings: Cursor=%d, want 1", m.Cursor)
	}
}

// TestSetScanProgressEdges covers idle → running → finished + the
// clamping for total<=0 and overshoots.
func TestSetScanProgressEdges(t *testing.T) {
	m := NewModel(ModeInteractive)

	m = m.SetScanProgress(0, 0)
	if m.ScanRunning || m.ScanProgress != 0 {
		t.Errorf("idle: running=%v progress=%v", m.ScanRunning, m.ScanProgress)
	}

	m = m.SetScanProgress(50, 100)
	if !m.ScanRunning || m.ScanProgress != 0.5 {
		t.Errorf("mid: running=%v progress=%v", m.ScanRunning, m.ScanProgress)
	}

	m = m.SetScanProgress(100, 100)
	if m.ScanRunning {
		t.Errorf("complete: running=true, want false")
	}
	if m.ScanProgress != 1 {
		t.Errorf("complete: progress=%v, want 1", m.ScanProgress)
	}

	m = m.SetScanProgress(150, 100)
	if m.ScanProgress != 1 {
		t.Errorf("overshoot: progress=%v, want clamped to 1", m.ScanProgress)
	}
}

// TestSortedSeveritiesOrder pins critical → high → medium → low
// → info. View depends on this ordering to render the bar chart
// top-down.
func TestSortedSeveritiesOrder(t *testing.T) {
	m := NewModel(ModeInteractive)
	// Insert in a scrambled order; expect canonical output.
	for _, s := range []Severity{SeverityInfo, SeverityCritical, SeverityLow, SeverityHigh, SeverityMedium} {
		m.TriageCounts[s] = 1
	}
	got := m.SortedSeverities()
	want := []Severity{SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestFormatProgressLine pins the rendered progress text.
func TestFormatProgressLine(t *testing.T) {
	if got := formatProgressLine(0, 0, 0); got != "idle" {
		t.Errorf("idle: %q", got)
	}
	if got := formatProgressLine(94, 200, 0.47); got != " 47% (94 / 200)" {
		t.Errorf("running: %q", got)
	}
}

// TestModelDeterministicNow proves Now is injectable for tests.
func TestModelDeterministicNow(t *testing.T) {
	fixed := time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC)
	m := NewModel(ModeInteractive)
	m.Now = func() time.Time { return fixed }
	if got := m.Now(); !got.Equal(fixed) {
		t.Errorf("injected Now: %v, want %v", got, fixed)
	}
}
