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

// schemaPeek is the minimum-shape struct we use for a first-
// pass schema sniff. Avoids spending a full Unmarshal on a
// line whose schema doesn't match anything we know.
type schemaPeek struct {
	Schema string `json:"schema"`
}

// tuiRecordRecord is the v1.41 elsereno-tui-record/v1 shape.
// Mirrors recordEvent in internal/tui/recorder.go; we keep a
// dedicated decode struct here to avoid an import cycle (the
// recorder imports tui types, the feeds package imports the
// same — circular).
type tuiRecordRecord struct {
	Schema    string `json:"schema"`
	TS        string `json:"ts"`
	Type      string `json:"type"`
	Line      string `json:"line,omitempty"`
	Mode      string `json:"mode,omitempty"`
	Err       string `json:"err,omitempty"`
	Completed *int64 `json:"completed,omitempty"`
	Total     *int64 `json:"total,omitempty"`
	// Finding is decoded as raw JSON so we can pass it to
	// json.Unmarshal again into a core.Finding without
	// double-allocating.
	Finding json.RawMessage `json:"finding,omitempty"`
}

const tuiRecordSchema = "elsereno-tui-record/v1"

// parseRecord converts one NDJSON line to a tea.Msg. Returns
// FindingMsg on success, AuditMsg with a friendly error on
// failure. Returning a synthetic AuditMsg lets the operator see
// per-line skips inline rather than aborting the whole stream.
//
// v1.42+ multi-schema support:
//   - `ndjson:v1`              → FindingMsg (the original
//     scan-output emitter shape)
//   - `elsereno-tui-record/v1` → type-tagged dispatch:
//     FindingMsg / AuditMsg /
//     ScanProgressMsg / FeedClosedMsg
//     (round-trip from v1.41
//     tui --record).
//
// The second return is the underlying error (nil on success);
// callers that want to short-circuit on parse failure can use it.
func parseRecord(line []byte, lineNo int) (tea.Msg, error) {
	var peek schemaPeek
	if err := json.Unmarshal(line, &peek); err != nil {
		return tui.AuditMsg{
			Line: fmt.Sprintf("ndjson: skipped malformed line %d: %v", lineNo, err),
		}, err
	}
	switch peek.Schema {
	case ndjson.Contract:
		return parseScanFinding(line, lineNo)
	case tuiRecordSchema:
		return parseTUIRecord(line, lineNo)
	default:
		return tui.AuditMsg{
			Line: fmt.Sprintf("ndjson: skipped line %d: unknown schema %q (want %q or %q)",
				lineNo, peek.Schema, ndjson.Contract, tuiRecordSchema),
		}, fmt.Errorf("schema mismatch: %q", peek.Schema)
	}
}

// parseScanFinding decodes one `ndjson:v1` line — the
// original scan-output shape that v1.29 chunk 3's --replay
// reads.
func parseScanFinding(line []byte, lineNo int) (tea.Msg, error) {
	var rec ndjson.Record
	if err := json.Unmarshal(line, &rec); err != nil {
		return tui.AuditMsg{
			Line: fmt.Sprintf("ndjson: skipped malformed line %d: %v", lineNo, err),
		}, err
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

// parseTUIRecord decodes one `elsereno-tui-record/v1` line.
// Dispatches on the `type` field. Unknown types fall through
// to a friendly AuditMsg so the operator sees what was
// skipped (forward-compat: a future schema-bump that adds
// new types still streams through the older replayer).
func parseTUIRecord(line []byte, lineNo int) (tea.Msg, error) {
	var rec tuiRecordRecord
	if err := json.Unmarshal(line, &rec); err != nil {
		return tui.AuditMsg{
			Line: fmt.Sprintf("tui-record: skipped malformed line %d: %v", lineNo, err),
		}, err
	}
	switch rec.Type {
	case "finding":
		var f core.Finding
		if err := json.Unmarshal(rec.Finding, &f); err != nil {
			return tui.AuditMsg{
				Line: fmt.Sprintf("tui-record: line %d: bad finding payload: %v", lineNo, err),
			}, err
		}
		return tui.FindingMsg{Finding: f}, nil
	case "audit":
		return tui.AuditMsg{Line: rec.Line}, nil
	case "scan_progress":
		var c, t int64
		if rec.Completed != nil {
			c = *rec.Completed
		}
		if rec.Total != nil {
			t = *rec.Total
		}
		return tui.ScanProgressMsg{Completed: c, Total: t}, nil
	case "feed_closed":
		var feedErr error
		if rec.Err != "" {
			feedErr = fmt.Errorf("%s", rec.Err)
		}
		return tui.FeedClosedMsg{Mode: tui.Mode(rec.Mode), Err: feedErr}, nil
	default:
		return tui.AuditMsg{
			Line: fmt.Sprintf("tui-record: skipped line %d: unknown type %q",
				lineNo, rec.Type),
		}, fmt.Errorf("unknown type: %q", rec.Type)
	}
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
