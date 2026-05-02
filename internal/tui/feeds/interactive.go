//go:build !mini

package feeds

import (
	"context"
	"fmt"
	"sync/atomic"

	tea "github.com/charmbracelet/bubbletea"

	"local/elsereno/internal/core"
	"local/elsereno/internal/scanner"
	"local/elsereno/internal/tui"
)

// Interactive runs a scanner.Scanner from inside the TUI and
// funnels its findings + progress + errors into tea.Msg events
// that the Model folds into the UI.
//
// Pairs with the v1.30-chunk-3 `elsereno tui --input list:FILE`
// flag — operators can scan + triage in one process without
// piping `scan --output-format ndjson | tui --feed -`.
//
// Closure: when the scanner finishes the runner emits
// FeedClosedMsg{Mode: ModeInteractive}; the TUI keeps running
// so the operator can review findings. q quits the program.
type Interactive struct {
	// Targets is the resolved list to probe. The CLI populates
	// this from --input list:FILE before constructing the feed
	// so a missing-file error surfaces before the alt screen
	// takes over.
	Targets []core.Target
	// Probe is the per-target probe function. Production calls
	// banner.Default().Probe; tests inject a stub that emits
	// deterministic findings.
	Probe scanner.Probe
	// Options tunes scanner concurrency. Zero values inherit
	// scanner package defaults (8 concurrent targets etc.).
	Options scanner.Options
}

// Name implements tui.Feed.
func (i Interactive) Name() string {
	return fmt.Sprintf("interactive (%d targets)", len(i.Targets))
}

// Run implements tui.Feed. Spawns the scanner, drains findings
// + errs, emits one FindingMsg per finding + ScanProgressMsg
// as the completed counter advances + AuditMsg per scanner
// error + final ScanProgressMsg{Total: 0} on close.
func (i Interactive) Run(ctx context.Context, emit func(tea.Msg)) error {
	if len(i.Targets) == 0 {
		// Nothing to scan; emit an audit line so the operator
		// sees why the panes stay empty rather than a silent
		// run.
		emit(tui.AuditMsg{Line: "interactive: no targets to scan"})
		return nil
	}

	scn := scanner.New(i.Options)
	total := int64(len(i.Targets))
	var completed atomic.Int64

	// Initial progress so the bar renders immediately at 0/N
	// instead of "idle" — operators should see a scan started.
	emit(tui.ScanProgressMsg{Completed: 0, Total: total})

	findings, errs := scn.Run(ctx, i.Targets, i.Probe)

	// Drain both channels until both close. The scanner's Run
	// closes findings + errs when done; we use a 2-phase nil-
	// channel idiom to detect closure without spinning.
	for findings != nil || errs != nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case f, ok := <-findings:
			if !ok {
				findings = nil
				continue
			}
			emit(tui.FindingMsg{Finding: f})
			done := completed.Add(1)
			emit(tui.ScanProgressMsg{Completed: done, Total: total})
		case e, ok := <-errs:
			if !ok {
				errs = nil
				continue
			}
			// Per-target errors are non-fatal: they reach the
			// audit pane so the operator sees what happened
			// without aborting the scan. Mirrors batch
			// `scan`'s behaviour (warn-and-continue).
			emit(tui.AuditMsg{Line: fmt.Sprintf("scan: %v", e)})
		}
	}

	// Final progress = idle so the bar stops "running" once
	// every target has been probed.
	emit(tui.ScanProgressMsg{Completed: completed.Load(), Total: 0})
	return nil
}
