//go:build !mini

package tui

import (
	"bytes"
	"io"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/exp/teatest"

	"local/elsereno/internal/core"
)

// Program-level integration tests for the TUI runner. v1.33
// chunk 1. The component-level tests in model_test.go +
// update_test.go + view_test.go pin the public surface; this
// file drives the actual bubbletea program through teatest +
// asserts on the rendered output + final model state.
//
// teatest is the upstream-supported harness for bubbletea
// programs: NewTestModel runs the model in a goroutine,
// teatest.WaitFor polls the output buffer for a regex / byte
// pattern, tm.Send injects tea.Msg, tm.Type injects keystrokes.
// We bypass the runner.Run wrapper because teatest manages the
// program lifecycle itself; the feed goroutine is replaced by
// direct tm.Send calls so each test stays deterministic.

const (
	// Standard test terminal — wide enough to render every
	// pane without truncation, tall enough to fit the full
	// vertical layout (header + scan + triage + findings +
	// audit + footer).
	testTermWidth  = 120
	testTermHeight = 40

	// teatest WaitFor budget. Generous enough that a slow CI
	// runner doesn't false-fail; tight enough that a real
	// regression doesn't hang the suite.
	waitDuration  = 2 * time.Second
	waitCheckTick = 10 * time.Millisecond
)

// readAll drains the test program's output buffer. teatest
// returns an io.Reader that's safe to drain after Quit/
// WaitFinished.
func readAll(t *testing.T, r io.Reader) []byte {
	t.Helper()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	return b
}

// asTUIModelFinal pulls the concrete Model out of the final
// tea.Model returned by FinalModel. Tests that assert on
// model state hit this; tests that only assert on rendered
// bytes don't.
func asTUIModelFinal(t *testing.T, fm tea.Model) Model {
	t.Helper()
	m, ok := fm.(Model)
	if !ok {
		t.Fatalf("FinalModel = %T, want Model", fm)
	}
	return m
}

// TestProgram_QuitsOnQ — boots the program, sends `q`, asserts
// the program terminates and the final model has Quitting=true.
// This is the smallest end-to-end exercise: the bubbletea
// loop, the keypress wiring, and the Quit cmd all need to
// work for this to pass.
func TestProgram_QuitsOnQ(t *testing.T) {
	tm := teatest.NewTestModel(t, NewModel(ModeInteractive),
		teatest.WithInitialTermSize(testTermWidth, testTermHeight),
	)
	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	tm.WaitFinished(t, teatest.WithFinalTimeout(waitDuration))

	fm := asTUIModelFinal(t, tm.FinalModel(t))
	if !fm.Quitting {
		t.Errorf("Quitting=false; expected the q-key to set it before tea.Quit")
	}
}

// TestProgram_QuitsOnCtrlC — ctrl+c is the universal "get me
// out" key on every TTY app. Pin it explicitly so a future
// keymap refactor can't drop it.
func TestProgram_QuitsOnCtrlC(t *testing.T) {
	tm := teatest.NewTestModel(t, NewModel(ModeInteractive),
		teatest.WithInitialTermSize(testTermWidth, testTermHeight),
	)
	tm.Send(tea.KeyMsg{Type: tea.KeyCtrlC})
	tm.WaitFinished(t, teatest.WithFinalTimeout(waitDuration))

	fm := asTUIModelFinal(t, tm.FinalModel(t))
	if !fm.Quitting {
		t.Errorf("Quitting=false on ctrl+c")
	}
}

// TestProgram_RendersHeaderAndPanes — pin the rendered output
// at startup. Operators rely on the four pane labels showing
// up immediately; a layout regression would shift them.
func TestProgram_RendersHeaderAndPanes(t *testing.T) {
	tm := teatest.NewTestModel(t, NewModel(ModeInteractive),
		teatest.WithInitialTermSize(testTermWidth, testTermHeight),
	)
	t.Cleanup(func() { _ = tm.Quit() })

	// Wait for the full first render. teatest delivers
	// WindowSizeMsg before the first View; WaitFor polls the
	// growing output buffer until the condition matches.
	teatest.WaitFor(t, tm.Output(), func(out []byte) bool {
		return bytes.Contains(out, []byte("Findings:")) &&
			bytes.Contains(out, []byte("Audit feed:")) &&
			bytes.Contains(out, []byte("Triage:")) &&
			bytes.Contains(out, []byte("Scan:"))
	}, teatest.WithDuration(waitDuration), teatest.WithCheckInterval(waitCheckTick))
}

// TestProgram_RendersFindingMsg — sends a FindingMsg and
// verifies the protocol name reaches the rendered output.
// This pins the FindingMsg → Update → AddFinding → View
// chain end-to-end (the component tests cover each link
// individually).
func TestProgram_RendersFindingMsg(t *testing.T) {
	tm := teatest.NewTestModel(t, NewModel(ModeInteractive),
		teatest.WithInitialTermSize(testTermWidth, testTermHeight),
	)
	t.Cleanup(func() { _ = tm.Quit() })

	tm.Send(FindingMsg{Finding: core.Finding{
		ID:       core.UUID("aaaa1111"),
		Protocol: "modbus",
		Severity: core.Severity("high"),
		Score:    85,
	}})

	teatest.WaitFor(t, tm.Output(), func(out []byte) bool {
		return bytes.Contains(out, []byte("modbus"))
	}, teatest.WithDuration(waitDuration), teatest.WithCheckInterval(waitCheckTick))
}

// TestProgram_RendersAuditMsg — sends an AuditMsg and verifies
// the line lands in the audit pane. Mirrors the FindingMsg
// test but exercises the parallel branch in Update.
func TestProgram_RendersAuditMsg(t *testing.T) {
	tm := teatest.NewTestModel(t, NewModel(ModeInteractive),
		teatest.WithInitialTermSize(testTermWidth, testTermHeight),
	)
	t.Cleanup(func() { _ = tm.Quit() })

	tm.Send(AuditMsg{Line: "vault: unlocked by alice"})

	teatest.WaitFor(t, tm.Output(), func(out []byte) bool {
		return bytes.Contains(out, []byte("vault: unlocked by alice"))
	}, teatest.WithDuration(waitDuration), teatest.WithCheckInterval(waitCheckTick))
}

// TestProgram_FilterEditCycle — pins the v1.30-chunk-4
// audit-pane filter end-to-end. Switches focus to the audit
// pane, types `/scan`, hits Enter, asserts AuditFilter has
// been committed and the rendered output reflects it.
func TestProgram_FilterEditCycle(t *testing.T) {
	tm := teatest.NewTestModel(t, NewModel(ModeInteractive),
		teatest.WithInitialTermSize(testTermWidth, testTermHeight),
	)

	// Push some audit lines so the filter has something to
	// narrow.
	tm.Send(AuditMsg{Line: "scan started"})
	tm.Send(AuditMsg{Line: "vault unlocked"})
	tm.Send(AuditMsg{Line: "scan complete"})

	// Cycle focus from the default findings pane to the audit
	// pane: Tab → triage → audit (2 tabs).
	tm.Send(tea.KeyMsg{Type: tea.KeyTab})
	tm.Send(tea.KeyMsg{Type: tea.KeyTab})

	// Enter filter-edit mode + type "scan" + commit.
	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'/'}})
	tm.Type("scan")
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})

	// Wait for the committed-filter header to render.
	teatest.WaitFor(t, tm.Output(), func(out []byte) bool {
		return bytes.Contains(out, []byte("/scan"))
	}, teatest.WithDuration(waitDuration), teatest.WithCheckInterval(waitCheckTick))

	// Drain + quit + assert on final model state.
	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	tm.WaitFinished(t, teatest.WithFinalTimeout(waitDuration))

	fm := asTUIModelFinal(t, tm.FinalModel(t))
	if fm.AuditFilter != "scan" {
		t.Errorf("AuditFilter = %q, want %q", fm.AuditFilter, "scan")
	}
	if fm.FilterEditing {
		t.Errorf("FilterEditing=true after commit; expected reset")
	}
}

// TestProgram_TabCyclesFocus — visual / state assertion on
// the Tab keybinding. Sends Tab three times and asserts the
// final FocusedPane.
func TestProgram_TabCyclesFocus(t *testing.T) {
	tm := teatest.NewTestModel(t, NewModel(ModeInteractive),
		teatest.WithInitialTermSize(testTermWidth, testTermHeight),
	)

	tm.Send(tea.KeyMsg{Type: tea.KeyTab})
	tm.Send(tea.KeyMsg{Type: tea.KeyTab})
	tm.Send(tea.KeyMsg{Type: tea.KeyTab})

	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	tm.WaitFinished(t, teatest.WithFinalTimeout(waitDuration))

	fm := asTUIModelFinal(t, tm.FinalModel(t))
	// Default pane = PaneFindings; +3 tabs → PaneScan → PaneFindings(wrap):
	//   PaneFindings(0) → PaneTriage(1) → PaneAudit(2) → PaneScan(3).
	if fm.FocusedPane != PaneScan {
		t.Errorf("FocusedPane = %v, want PaneScan after 3 tabs", fm.FocusedPane)
	}
}

// TestProgram_FindingMsg_BumpsTriageCount — pins the
// FindingMsg → severity-band → counter chain. A score of 95
// must land in the Critical bucket and the chip must render.
func TestProgram_FindingMsg_BumpsTriageCount(t *testing.T) {
	tm := teatest.NewTestModel(t, NewModel(ModeInteractive),
		teatest.WithInitialTermSize(testTermWidth, testTermHeight),
	)
	t.Cleanup(func() { _ = tm.Quit() })

	tm.Send(FindingMsg{Finding: core.Finding{Score: 95, Protocol: "s7"}})

	teatest.WaitFor(t, tm.Output(), func(out []byte) bool {
		return bytes.Contains(out, []byte("critical"))
	}, teatest.WithDuration(waitDuration), teatest.WithCheckInterval(waitCheckTick))
}

// TestProgram_TerminalTooSmall — render path branches on
// width<50 || height<10. Pin the friendly message that
// surfaces when an operator launches the TUI in a tiny
// terminal.
func TestProgram_TerminalTooSmall(t *testing.T) {
	tm := teatest.NewTestModel(t, NewModel(ModeInteractive),
		teatest.WithInitialTermSize(20, 5),
	)
	t.Cleanup(func() { _ = tm.Quit() })

	teatest.WaitFor(t, tm.Output(), func(out []byte) bool {
		return bytes.Contains(out, []byte("Terminal too small"))
	}, teatest.WithDuration(waitDuration), teatest.WithCheckInterval(waitCheckTick))
}

// TestProgram_FullSession_FinalOutputIsCleanASCII — drains
// the FinalOutput after a complete session and verifies that
// no diagnostic noise (panic stack, error prints) leaked
// onto the terminal stream. Operators copying terminal logs
// to bug reports get clean output.
func TestProgram_FullSession_FinalOutputIsCleanASCII(t *testing.T) {
	tm := teatest.NewTestModel(t, NewModel(ModeInteractive),
		teatest.WithInitialTermSize(testTermWidth, testTermHeight),
	)
	tm.Send(FindingMsg{Finding: core.Finding{Score: 50, Protocol: "modbus"}})
	tm.Send(AuditMsg{Line: "scan: complete"})
	tm.Send(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	tm.WaitFinished(t, teatest.WithFinalTimeout(waitDuration))

	out := readAll(t, tm.FinalOutput(t, teatest.WithFinalTimeout(waitDuration)))
	for _, bad := range [][]byte{
		[]byte("panic:"),
		[]byte("runtime error"),
		[]byte("goroutine "),
	} {
		if bytes.Contains(out, bad) {
			t.Errorf("diagnostic noise leaked: %q seen in output", bad)
		}
	}
}
