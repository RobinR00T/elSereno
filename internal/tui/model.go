//go:build !mini

package tui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"local/elsereno/internal/core"
)

// Mode identifies which feed populates the Model. Set at
// startup; the TUI doesn't switch modes mid-session.
type Mode string

// Mode values.
const (
	ModeInteractive Mode = "interactive"
	ModeReplay      Mode = "replay"
	ModeFeed        Mode = "feed"
	ModeWatch       Mode = "watch"
)

// Pane identifies the currently-focused panel in the layout.
// Tab cycles forward; Shift+Tab cycles back. The selected pane
// captures keyboard input (j/k for navigation, etc.).
type Pane int

// Pane values, in tab-cycle order.
const (
	PaneFindings Pane = iota
	PaneTriage
	PaneAudit
	PaneScan
)

// Severity buckets the dashboard's triage uses. Mirrored here so
// the TUI's bucket counters stay in sync with /api/v1/triage.
type Severity string

// Severity values (high → low).
const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Model is the bubbletea state container. Pass to tea.NewProgram
// + drive via the standard Update / View loop.
//
// All fields are exported so tests in package tui_test can drive
// the Model directly (drop-in fixtures rather than rebuilding
// state via the full event sequence).
type Model struct {
	// ModeName is the active feed mode. Display-only after init.
	ModeName Mode

	// Findings is the rolling window of recent findings. Capped
	// at MaxFindings (default 200) — older entries are dropped
	// rather than scrolled, so the panel stays responsive on
	// long-running scans. Operators wanting the full history
	// query the dashboard / DB.
	Findings []core.Finding

	// Cursor is the selected row in the Findings panel.
	Cursor int

	// TriageCounts is the per-severity bucket count. Updated on
	// every Finding arrival.
	TriageCounts map[Severity]int

	// AuditEvents is the rolling window of recent audit events.
	// Capped at MaxAuditEvents (default 100). Each entry is a
	// short rendered line; the TUI doesn't need the full Entry
	// shape because audit feed is observe-only.
	AuditEvents []string

	// ScanProgress 0..1. Populated only in interactive mode
	// when the operator launches a scan from inside.
	ScanProgress float64

	// ScanRunning is true between scan-start + scan-end events.
	ScanRunning bool

	// ScanTotal + ScanCompleted track the underlying scanner's
	// progress (mirrors what `elsereno scan` prints to stderr).
	ScanTotal     int64
	ScanCompleted int64

	// FocusedPane is the active panel. Tab cycles.
	FocusedPane Pane

	// AuditFilter (v1.30 chunk 4) is a substring the operator
	// typed via `/` on the audit pane. When non-empty, only
	// audit lines containing the substring (case-insensitive)
	// render. Esc clears it. Empty (default) shows everything.
	AuditFilter string

	// FilterEditing (v1.30 chunk 4) is true between `/` and the
	// terminating Enter / Esc. While true, every printable key
	// extends FilterDraft; Backspace deletes; Enter commits;
	// Esc cancels. The view renders the live draft so the
	// operator sees what they're typing.
	FilterEditing bool

	// FilterDraft (v1.30 chunk 4) is the in-progress filter
	// string, only meaningful while FilterEditing is true.
	FilterDraft string

	// Width + Height are the terminal dimensions. Updated on
	// tea.WindowSizeMsg.
	Width  int
	Height int

	// Quitting signals tea.Quit on the next Update; used so the
	// TUI shuts cleanly even if the feed goroutine is still
	// emitting events.
	Quitting bool

	// Now is injected so tests get deterministic timestamps.
	// Defaults to time.Now in init.
	Now func() time.Time

	// MaxFindings + MaxAuditEvents bound the rolling windows.
	MaxFindings    int
	MaxAuditEvents int
}

// NewModel returns a Model initialised with sensible defaults
// for mode. Caller hands it to tea.NewProgram.
func NewModel(mode Mode) Model {
	return Model{
		ModeName:       mode,
		Findings:       []core.Finding{},
		TriageCounts:   map[Severity]int{},
		AuditEvents:    []string{},
		FocusedPane:    PaneFindings,
		Now:            func() time.Time { return time.Now().UTC() },
		MaxFindings:    200,
		MaxAuditEvents: 100,
	}
}

// Init implements tea.Model. The TUI itself doesn't subscribe to
// tickers from Init — feed goroutines drive the state via
// outboundMessages (FindingMsg, AuditMsg, ScanProgressMsg, etc.).
// The runner wires the channel; see runner.go.
func (m Model) Init() tea.Cmd { return nil }

// AddFinding appends a new finding + bumps its severity bucket
// + advances the rolling window. Returns the updated Model.
func (m Model) AddFinding(f core.Finding) Model {
	m.Findings = append(m.Findings, f)
	if len(m.Findings) > m.MaxFindings {
		m.Findings = m.Findings[len(m.Findings)-m.MaxFindings:]
		// Adjust cursor so it doesn't dangle past the trimmed slice.
		if m.Cursor > 0 {
			m.Cursor--
		}
	}
	if m.TriageCounts == nil {
		m.TriageCounts = map[Severity]int{}
	}
	m.TriageCounts[severityOf(f)]++
	return m
}

// AddAuditEvent appends a rendered audit-event line + advances
// the rolling window.
func (m Model) AddAuditEvent(line string) Model {
	m.AuditEvents = append(m.AuditEvents, line)
	if len(m.AuditEvents) > m.MaxAuditEvents {
		m.AuditEvents = m.AuditEvents[len(m.AuditEvents)-m.MaxAuditEvents:]
	}
	return m
}

// SetScanProgress folds a scan-progress event into the Model.
// total = 0 ends the scan; non-zero updates the bar.
func (m Model) SetScanProgress(completed, total int64) Model {
	m.ScanCompleted = completed
	m.ScanTotal = total
	if total <= 0 {
		m.ScanRunning = false
		m.ScanProgress = 0
		return m
	}
	m.ScanRunning = completed < total
	m.ScanProgress = float64(completed) / float64(total)
	if m.ScanProgress > 1 {
		m.ScanProgress = 1
	}
	if m.ScanProgress < 0 {
		m.ScanProgress = 0
	}
	return m
}

// CycleFocus advances the focused pane in tab order. Wraps.
func (m Model) CycleFocus(reverse bool) Model {
	if reverse {
		m.FocusedPane--
		if m.FocusedPane < PaneFindings {
			m.FocusedPane = PaneScan
		}
		return m
	}
	m.FocusedPane++
	if m.FocusedPane > PaneScan {
		m.FocusedPane = PaneFindings
	}
	return m
}

// MoveCursor moves the findings cursor by delta, clamped to
// [0, len(Findings)-1].
func (m Model) MoveCursor(delta int) Model {
	m.Cursor += delta
	if m.Cursor < 0 {
		m.Cursor = 0
	}
	if m.Cursor >= len(m.Findings) && len(m.Findings) > 0 {
		m.Cursor = len(m.Findings) - 1
	}
	return m
}

// SortedSeverities returns the bucket keys in canonical priority
// order so View renders them deterministically.
func (m Model) SortedSeverities() []Severity {
	out := make([]Severity, 0, len(m.TriageCounts))
	for k := range m.TriageCounts {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		return severityRank(out[i]) < severityRank(out[j])
	})
	return out
}

// severityOf maps a Finding's score to a Severity. Mirrors the
// scoring/severity bands the dashboard already uses (ADR-006).
func severityOf(f core.Finding) Severity {
	switch {
	case f.Score >= 90:
		return SeverityCritical
	case f.Score >= 70:
		return SeverityHigh
	case f.Score >= 50:
		return SeverityMedium
	case f.Score >= 25:
		return SeverityLow
	default:
		return SeverityInfo
	}
}

func severityRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 0
	case SeverityHigh:
		return 1
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 3
	case SeverityInfo:
		return 4
	}
	return 99
}

// formatProgressLine produces the `47% (94 / 200)` body of the
// scan progress bar, used by View. Pulled out for unit-testing.
func formatProgressLine(completed, total int64, percent float64) string {
	if total <= 0 {
		return "idle"
	}
	return fmt.Sprintf("%3.0f%% (%d / %d)", percent*100, completed, total)
}

// FilteredAuditEvents returns the AuditEvents slice constrained
// by AuditFilter. Empty filter → returns AuditEvents as-is.
// Match is case-insensitive substring (operators rarely care
// about exact case in audit feeds; `/vault` finds both
// "vault_unlock" and "Vault unlocked").
func (m Model) FilteredAuditEvents() []string {
	if m.AuditFilter == "" {
		return m.AuditEvents
	}
	needle := strings.ToLower(m.AuditFilter)
	out := make([]string, 0, len(m.AuditEvents))
	for _, line := range m.AuditEvents {
		if strings.Contains(strings.ToLower(line), needle) {
			out = append(out, line)
		}
	}
	return out
}
