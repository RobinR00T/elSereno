//go:build !mini

package feeds

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"local/elsereno/internal/core"
	"local/elsereno/internal/outputs/ndjson"
	"local/elsereno/internal/tui"
)

// Replay reads an ndjson:v1 capture file from disk and emits one
// tui.FindingMsg per record. Pairs with `elsereno scan
// --output-format ndjson > file.ndjson`; the operator can then
// drive the TUI from that capture for triage / demos / training
// without re-running the scan.
//
// Replay honours a Rate (lines per second) for slow-motion
// playback. Rate <= 0 → as fast as possible. Useful for demos
// where the scan finished in 200 ms but the audience needs to
// see findings appear.
//
// On parse error, the bad line is converted into a synthetic
// AuditMsg ("replay: skipped malformed line N: …") rather than
// terminating the feed — a single corrupted entry shouldn't kill
// a long capture. The first I/O error (read failure, EOF
// excepted) terminates the feed and is returned via Run.
type Replay struct {
	// Path is the on-disk file. Required.
	Path string
	// Rate is the playback rate in lines per second. 0 (the
	// default) plays as fast as the goroutine schedules.
	Rate float64
}

// Name implements tui.Feed.
func (r Replay) Name() string {
	return "replay " + r.Path
}

// Run implements tui.Feed. Opens Path, streams lines, converts
// each to a tui.FindingMsg + emits.
func (r Replay) Run(ctx context.Context, emit func(tea.Msg)) error {
	if r.Path == "" {
		return errors.New("replay: empty Path")
	}
	f, err := os.Open(r.Path) //nolint:gosec // operator-supplied path is intended.
	if err != nil {
		return fmt.Errorf("replay: open %s: %w", r.Path, err)
	}
	defer func() { _ = f.Close() }()

	return r.stream(ctx, f, emit)
}

// stream is split out so tests drive an io.Reader directly.
func (r Replay) stream(ctx context.Context, src io.Reader, emit func(tea.Msg)) error {
	scanner := bufio.NewScanner(src)
	// Findings can carry large payload metadata; bump the buffer
	// so single lines up to 4 MiB succeed. Anything larger is
	// almost certainly corruption.
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)

	var pace time.Duration
	if r.Rate > 0 {
		pace = time.Duration(float64(time.Second) / r.Rate)
	}

	lineNo := 0
	for scanner.Scan() {
		lineNo++
		// Honour cancellation between every line so a long
		// replay terminates promptly on q / ctrl+c.
		if ctx.Err() != nil {
			return ctx.Err()
		}
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		msg, perr := parseRecord(line, lineNo)
		emit(msg)
		_ = perr // parseRecord embeds the error context in the AuditMsg.
		if pace > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(pace):
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("replay: scan: %w", err)
	}
	return nil
}

// parseRecord converts one NDJSON line to a tea.Msg. Returns
// FindingMsg on success, AuditMsg with a friendly error on
// failure. Returning a synthetic AuditMsg lets the operator see
// per-line skips inline rather than aborting the whole replay.
//
// The second return is the underlying error (nil on success);
// callers that want to short-circuit on parse failure can use it.
func parseRecord(line []byte, lineNo int) (tea.Msg, error) {
	var rec ndjson.Record
	if err := json.Unmarshal(line, &rec); err != nil {
		return tui.AuditMsg{
			Line: fmt.Sprintf("replay: skipped malformed line %d: %v", lineNo, err),
		}, err
	}
	if rec.Schema != ndjson.Contract {
		return tui.AuditMsg{
			Line: fmt.Sprintf("replay: skipped line %d: unknown schema %q (want %q)",
				lineNo, rec.Schema, ndjson.Contract),
		}, fmt.Errorf("schema mismatch: %q", rec.Schema)
	}

	created := time.Time{}
	if rec.CreatedAt != "" {
		if t, err := time.Parse(time.RFC3339Nano, rec.CreatedAt); err == nil {
			created = t
		}
		// Bad timestamps are non-fatal; the TUI tolerates the
		// zero value.
	}

	return tui.FindingMsg{
		Finding: core.Finding{
			RunID:     core.UUID(rec.Run),
			TargetID:  core.UUID(rec.Target),
			Protocol:  rec.Protocol,
			Severity:  core.Severity(rec.Severity),
			Score:     rec.Score,
			Factors:   rec.Factors,
			CreatedAt: created,
		},
	}, nil
}
