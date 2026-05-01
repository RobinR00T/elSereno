//go:build !mini

package feeds

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"local/elsereno/internal/core"
	"local/elsereno/internal/outputs/ndjson"
	"local/elsereno/internal/tui"
)

// streamNDJSON is the shared NDJSON line-pump used by Replay
// (file source) + Stdin (live source) + (later) Watch's
// transport-decoded SSE payloads. Every TUI feed that consumes
// the `ndjson:v1` schema funnels through this so the
// per-record parsing rules + skip behaviour stay consistent.
//
// pace > 0 introduces a wallclock delay between lines (slow
// playback for demos). pace == 0 streams as fast as the
// scheduler permits.
func streamNDJSON(ctx context.Context, src io.Reader, emit func(tea.Msg), pace time.Duration) error {
	scanner := bufio.NewScanner(src)
	// Findings can carry large payload metadata; bump the buffer
	// so single lines up to 4 MiB succeed. Anything larger is
	// almost certainly corruption.
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)

	lineNo := 0
	for scanner.Scan() {
		lineNo++
		// Honour cancellation between every line so a long
		// stream terminates promptly on q / ctrl+c.
		if ctx.Err() != nil {
			return ctx.Err()
		}
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		msg, _ := parseRecord(line, lineNo)
		emit(msg)
		if pace > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(pace):
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("ndjson stream: %w", err)
	}
	return nil
}

// parseRecord converts one NDJSON line to a tea.Msg. Returns
// FindingMsg on success, AuditMsg with a friendly error on
// failure. Returning a synthetic AuditMsg lets the operator see
// per-line skips inline rather than aborting the whole stream.
//
// The second return is the underlying error (nil on success);
// callers that want to short-circuit on parse failure can use it.
func parseRecord(line []byte, lineNo int) (tea.Msg, error) {
	var rec ndjson.Record
	if err := json.Unmarshal(line, &rec); err != nil {
		return tui.AuditMsg{
			Line: fmt.Sprintf("ndjson: skipped malformed line %d: %v", lineNo, err),
		}, err
	}
	if rec.Schema != ndjson.Contract {
		return tui.AuditMsg{
			Line: fmt.Sprintf("ndjson: skipped line %d: unknown schema %q (want %q)",
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

// paceFromRate converts lines-per-second into a per-line
// duration. <=0 → 0 (unbounded). Helper so feeds expose Rate
// uniformly without duplicating the conversion arithmetic.
func paceFromRate(linesPerSecond float64) time.Duration {
	if linesPerSecond <= 0 {
		return 0
	}
	return time.Duration(float64(time.Second) / linesPerSecond)
}
