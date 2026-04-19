// Package retention implements the per-class retention policy. The
// evidence rule is keep-if-referenced (an evidence row survives while
// any finding still references it) per section 7 of the brief.
package retention

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// ErrInvalidPolicy is returned when Policy values are outside
// [0, ~10 years]. Zero days means "never expire".
var ErrInvalidPolicy = errors.New("retention: invalid policy")

// Policy describes per-class retention in days.
type Policy struct {
	FindingsDays int
	EvidenceDays int
	RunsDays     int
}

// Validate rejects absurd values. Zero is allowed and means "never
// expire".
func (p Policy) Validate() error {
	const maxDays = 3650
	check := func(name string, d int) error {
		if d < 0 || d > maxDays {
			return fmt.Errorf("%w: %s=%d not in [0, %d]", ErrInvalidPolicy, name, d, maxDays)
		}
		return nil
	}
	if err := check("findings_days", p.FindingsDays); err != nil {
		return err
	}
	if err := check("evidence_days", p.EvidenceDays); err != nil {
		return err
	}
	if err := check("runs_days", p.RunsDays); err != nil {
		return err
	}
	return nil
}

// Cutoff computes the RFC3339-microsecond UTC timestamp before which
// rows of class `class` should be removed. Zero days returns the zero
// time to signal "never expire".
func (p Policy) Cutoff(now time.Time, class Class) time.Time {
	var d int
	switch class {
	case ClassFindings:
		d = p.FindingsDays
	case ClassEvidence:
		d = p.EvidenceDays
	case ClassRuns:
		d = p.RunsDays
	}
	if d <= 0 {
		return time.Time{}
	}
	return now.UTC().Add(-time.Duration(d) * 24 * time.Hour).Truncate(time.Microsecond)
}

// Class is the retention class.
type Class int

// Retention classes.
const (
	ClassFindings Class = iota
	ClassEvidence
	ClassRuns
)

// Pruner is the minimal interface the enforcer uses against the DB.
type Pruner interface {
	// PruneFindings removes findings with created_at < cutoff and
	// returns the count removed.
	PruneFindings(ctx context.Context, cutoff time.Time) (int64, error)
	// PruneEvidence removes evidence rows whose captured_at is before
	// cutoff AND whose finding_id is not referenced by any surviving
	// finding (keep-if-referenced).
	PruneEvidence(ctx context.Context, cutoff time.Time) (int64, error)
	// PruneRuns removes runs with finished_at < cutoff.
	PruneRuns(ctx context.Context, cutoff time.Time) (int64, error)
}

// Report is the per-class removal count returned by Enforce.
type Report struct {
	FindingsRemoved int64
	EvidenceRemoved int64
	RunsRemoved     int64
}

// Enforce applies the policy. The function is idempotent under a fixed
// `now` — it never re-removes already-removed rows.
func Enforce(ctx context.Context, now time.Time, p Policy, pr Pruner) (Report, error) {
	var r Report
	if err := p.Validate(); err != nil {
		return r, err
	}
	if c := p.Cutoff(now, ClassFindings); !c.IsZero() {
		n, err := pr.PruneFindings(ctx, c)
		if err != nil {
			return r, fmt.Errorf("retention: findings: %w", err)
		}
		r.FindingsRemoved = n
	}
	if c := p.Cutoff(now, ClassEvidence); !c.IsZero() {
		n, err := pr.PruneEvidence(ctx, c)
		if err != nil {
			return r, fmt.Errorf("retention: evidence: %w", err)
		}
		r.EvidenceRemoved = n
	}
	if c := p.Cutoff(now, ClassRuns); !c.IsZero() {
		n, err := pr.PruneRuns(ctx, c)
		if err != nil {
			return r, fmt.Errorf("retention: runs: %w", err)
		}
		r.RunsRemoved = n
	}
	return r, nil
}
