//go:build offensive

package dial

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"local/elsereno/internal/audit"
	"local/elsereno/internal/scope"
)

// BatchResult captures the per-number outcome of a wardialing
// batch. The zero Number is a parsing skip (blank line / comment).
type BatchResult struct {
	// Raw is the operator's input line, trimmed of whitespace.
	Raw string
	// Normalised is the digits-only form returned by Normalise.
	Normalised string
	// Decision is one of: "allow", "short", "blocked", "empty".
	Decision string
	// Reason is a human-readable detail operators can grep.
	Reason string
}

// Batch walks numbers in r and classifies each one against the
// dial guard (ADR-041). Every number — allowed or rejected —
// produces one audit Entry of type `offensive_dial` so the chain
// reflects the operator's full intent, not just the ones that
// would have gone through.
//
// The default disposition is "preview": this is a dry-run that
// never drives a modem. v1.2 wires an actual PSTN / VoIP
// delivery; for v1.1 we want the scope check, the seccomp
// sandbox, and the audit trail exercised end-to-end before we
// trust any dialling hardware.
type Batch struct {
	// Scope limits which numbers pass the blocked_numbers check.
	// Nil scope = no additional filter (the hard ≤3-digit block
	// still applies).
	Scope *scope.Scope
	// Writer is the audit sink. Required — the whole point of a
	// batch is that every decision is recorded.
	Writer audit.Writer
	// Actor is written into each audit entry. Usually currentActor().
	Actor string
	// Disposition is the `disposition` payload field. "preview" is
	// the default; an operator passing --accept-writes can flip it
	// to "delivery-requested" to record INTENT — the actual hardware
	// call is v1.2.
	Disposition string
	// Operation is the protocol-ish label emitted under
	// payload.operation. "dial_batch" for wardialing.
	Operation string
}

// Run streams numbers from r (one per line; `#` lines + blank
// lines skipped), validates each, and appends an audit entry per
// decision. Returns the per-number results in input order so the
// caller can render a summary.
//
// Errors from the audit writer are fatal (a broken chain is
// worse than a partial batch). Per-number decision errors
// (ErrShortNumber, ErrBlockedByScope) are NOT fatal — they're
// the common case for a big list.
func (b *Batch) Run(ctx context.Context, r io.Reader) ([]BatchResult, error) {
	if b.Writer == nil {
		return nil, errors.New("dial: Batch.Writer required")
	}
	if b.Disposition == "" {
		b.Disposition = "preview"
	}
	if b.Operation == "" {
		b.Operation = "dial_batch"
	}
	if b.Actor == "" {
		b.Actor = "system"
	}

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 4096), 128*1024)

	var out []BatchResult
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		raw := strings.TrimSpace(scanner.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		res := classify(raw, b.Scope)
		out = append(out, res)
		if err := b.audit(ctx, res); err != nil {
			return out, fmt.Errorf("dial: audit append: %w", err)
		}
	}
	if err := scanner.Err(); err != nil {
		return out, fmt.Errorf("dial: read numbers: %w", err)
	}
	return out, nil
}

// classify runs the dial guard for one number and maps the
// result to the flat BatchResult shape.
func classify(raw string, sc *scope.Scope) BatchResult {
	norm, err := Validate(raw, sc)
	switch {
	case err == nil:
		return BatchResult{Raw: raw, Normalised: norm, Decision: "allow", Reason: "passes guard"}
	case errors.Is(err, ErrEmpty):
		return BatchResult{Raw: raw, Normalised: "", Decision: "empty", Reason: err.Error()}
	case errors.Is(err, ErrShortNumber):
		return BatchResult{Raw: raw, Normalised: norm, Decision: "short", Reason: "≤3-digit hard block"}
	case errors.Is(err, ErrBlockedByScope):
		return BatchResult{Raw: raw, Normalised: norm, Decision: "blocked", Reason: "scope.blocked_numbers"}
	default:
		return BatchResult{Raw: raw, Normalised: norm, Decision: "error", Reason: err.Error()}
	}
}

// audit emits one entry per classified number. The payload
// captures the decision + normalised form + reason so an
// operator tailing the chain can reconstruct the batch without
// needing the original file.
func (b *Batch) audit(ctx context.Context, r BatchResult) error {
	payload := []byte(fmt.Sprintf(
		`{"category":"dial","operation":%q,"disposition":%q,`+
			`"decision":%q,"raw":%q,"normalised":%q,"reason":%q,`+
			`"captured_at":%q}`,
		b.Operation,
		b.Disposition,
		r.Decision,
		r.Raw,
		r.Normalised,
		r.Reason,
		time.Now().UTC().Format(time.RFC3339Nano),
	))
	_, err := b.Writer.Append(ctx, audit.Entry{
		EventType: audit.EventOffDial,
		Actor:     b.Actor,
		Payload:   payload,
	})
	return err
}

// Summary is the per-decision tally a CLI caller prints after a
// batch completes.
type Summary struct {
	Total   int
	Allow   int
	Short   int
	Blocked int
	Empty   int
	Errored int
}

// Summarise folds results into per-decision counts.
func Summarise(results []BatchResult) Summary {
	s := Summary{Total: len(results)}
	for _, r := range results {
		switch r.Decision {
		case "allow":
			s.Allow++
		case "short":
			s.Short++
		case "blocked":
			s.Blocked++
		case "empty":
			s.Empty++
		default:
			s.Errored++
		}
	}
	return s
}
