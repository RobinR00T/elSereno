//go:build !mini

package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// Styles centralises the lipgloss styles so the View functions
// stay readable + the visual identity is consistent across
// panes.
var styles = struct {
	header        lipgloss.Style
	pane          lipgloss.Style
	paneFocused   lipgloss.Style
	severityBadge lipgloss.Style
	cursorRow     lipgloss.Style
	progressFill  lipgloss.Style
	progressEmpty lipgloss.Style
	footer        lipgloss.Style
	mute          lipgloss.Style
}{
	header: lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("12")).
		PaddingLeft(1).PaddingRight(1),
	pane: lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("240")).
		Padding(0, 1),
	paneFocused: lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("12")).
		Padding(0, 1),
	severityBadge: lipgloss.NewStyle().
		Bold(true).
		PaddingLeft(1).PaddingRight(1),
	cursorRow:     lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("15")).Background(lipgloss.Color("236")),
	progressFill:  lipgloss.NewStyle().Foreground(lipgloss.Color("10")),
	progressEmpty: lipgloss.NewStyle().Foreground(lipgloss.Color("240")),
	footer:        lipgloss.NewStyle().Foreground(lipgloss.Color("241")).PaddingLeft(1),
	mute:          lipgloss.NewStyle().Foreground(lipgloss.Color("241")),
}

// View implements tea.Model. Renders the four panes (scan-
// progress, triage chips, findings table, audit feed) plus a
// header + footer.
func (m Model) View() string {
	if m.Quitting {
		return styles.mute.Render("(quitting…)\n")
	}
	if m.Width < 50 || m.Height < 10 {
		return styles.mute.Render("Terminal too small (min 50×10)\n")
	}

	header := styles.header.Render(fmt.Sprintf("ElSereno TUI — mode=%s", m.ModeName))

	// Scan progress bar (fixed height 3 lines).
	scanPane := m.renderScanPane()
	// Triage chips (fixed height 3 lines).
	triagePane := m.renderTriagePane()
	// Findings table (flex height).
	findingsPane := m.renderFindingsPane()
	// Audit feed (fixed bottom 8 lines).
	auditPane := m.renderAuditPane()

	footer := styles.footer.Render("Tab: focus  j/k: nav  /: filter audit  Esc: clear  q: quit")

	return strings.Join([]string{
		header,
		scanPane,
		triagePane,
		findingsPane,
		auditPane,
		footer,
	}, "\n")
}

func (m Model) renderScanPane() string {
	body := formatProgressLine(m.ScanCompleted, m.ScanTotal, m.ScanProgress)
	bar := renderProgressBar(m.ScanProgress, max(20, m.Width-12))
	style := styles.pane
	if m.FocusedPane == PaneScan {
		style = styles.paneFocused
	}
	return style.Width(max(40, m.Width-2)).
		Render(fmt.Sprintf("Scan: %s\n%s", body, bar))
}

func (m Model) renderTriagePane() string {
	chips := []string{}
	for _, sev := range m.SortedSeverities() {
		count := m.TriageCounts[sev]
		chip := styles.severityBadge.
			Background(severityColor(sev)).
			Foreground(lipgloss.Color("0")).
			Render(fmt.Sprintf("%s %d", sev, count))
		chips = append(chips, chip)
	}
	if len(chips) == 0 {
		chips = []string{styles.mute.Render("(no findings yet)")}
	}
	style := styles.pane
	if m.FocusedPane == PaneTriage {
		style = styles.paneFocused
	}
	return style.Width(max(40, m.Width-2)).
		Render("Triage:  " + strings.Join(chips, "  "))
}

func (m Model) renderFindingsPane() string {
	style := styles.pane
	if m.FocusedPane == PaneFindings {
		style = styles.paneFocused
	}
	height := max(8, m.Height-22)
	if len(m.Findings) == 0 {
		return style.Width(max(40, m.Width-2)).Height(height).
			Render("Findings:\n" + styles.mute.Render("  (waiting for first finding…)"))
	}
	// Show the latest N findings that fit in `height` rows. Cursor
	// is relative to the full Findings slice.
	visible := height - 2 // header + spacer
	if visible < 1 {
		visible = 1
	}
	start := 0
	if len(m.Findings) > visible {
		start = len(m.Findings) - visible
		// Ensure the cursor's finding is visible.
		if m.Cursor < start {
			start = m.Cursor
		}
	}
	// v2.31: header carries total count + cursor position so the
	// operator knows what fraction of findings is on-screen even
	// when the scroll window is small (incident triage often has
	// 100+ findings; "cursor on 87 of 312" is more useful than the
	// previous bare "Findings:" header).
	header := fmt.Sprintf("Findings (%d total · cursor on %d):  (▸ = active row)",
		len(m.Findings), m.Cursor+1)
	rows := []string{header}
	for i := start; i < len(m.Findings); i++ {
		f := m.Findings[i]
		// v2.31: severity column gets the colour-coded label
		// instead of the bare truncated string — at-a-glance
		// triage scan.
		sevLabel := lipgloss.NewStyle().
			Foreground(severityColor(Severity(f.Severity))).
			Render(truncate(string(f.Severity), 10))
		row := fmt.Sprintf(" %s  %3d  %-8s  %s",
			truncate(string(f.ID), 8),
			f.Score,
			truncate(f.Protocol, 8),
			sevLabel,
		)
		if i == m.Cursor && m.FocusedPane == PaneFindings {
			row = styles.cursorRow.Render("▸" + row)
		} else {
			row = " " + row
		}
		rows = append(rows, row)
	}
	return style.Width(max(40, m.Width-2)).Height(height).Render(strings.Join(rows, "\n"))
}

func (m Model) renderAuditPane() string {
	style := styles.pane
	if m.FocusedPane == PaneAudit {
		style = styles.paneFocused
	}
	height := 8
	header := "Audit feed:"
	switch {
	case m.FilterEditing:
		// Show the live draft with a trailing cursor so the
		// operator sees what they're typing.
		header = fmt.Sprintf("Audit feed:  /%s_  (Enter: apply, Esc: cancel)", m.FilterDraft)
	case m.AuditFilter != "":
		header = fmt.Sprintf("Audit feed:  /%s  (Esc: clear)", m.AuditFilter)
	}
	body := []string{header}
	events := m.FilteredAuditEvents()
	visible := height - 2
	start := 0
	if len(events) > visible {
		start = len(events) - visible
	}
	for i := start; i < len(events); i++ {
		body = append(body, " "+truncate(events[i], max(20, m.Width-6)))
	}
	if len(events) == 0 {
		switch {
		case m.AuditFilter != "":
			body = append(body, styles.mute.Render(fmt.Sprintf(" (no audit events match /%s)", m.AuditFilter)))
		default:
			body = append(body, styles.mute.Render(" (no audit events yet)"))
		}
	}
	return style.Width(max(40, m.Width-2)).Height(height).Render(strings.Join(body, "\n"))
}

func severityColor(s Severity) lipgloss.Color {
	switch s {
	case SeverityCritical:
		return lipgloss.Color("196") // bright red
	case SeverityHigh:
		return lipgloss.Color("208") // orange
	case SeverityMedium:
		return lipgloss.Color("220") // yellow
	case SeverityLow:
		return lipgloss.Color("75") // light blue
	case SeverityInfo:
		return lipgloss.Color("245") // grey
	}
	return lipgloss.Color("245")
}

func renderProgressBar(progress float64, width int) string {
	if width < 4 {
		width = 4
	}
	filled := int(progress * float64(width))
	if filled < 0 {
		filled = 0
	}
	if filled > width {
		filled = width
	}
	return styles.progressFill.Render(strings.Repeat("█", filled)) +
		styles.progressEmpty.Render(strings.Repeat("░", width-filled))
}

func truncate(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
