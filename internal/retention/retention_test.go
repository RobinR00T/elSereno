package retention_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"local/elsereno/internal/retention"
)

type fakePruner struct {
	findings, evidence, runs int64
	fErr, eErr, rErr         error
}

func (f *fakePruner) PruneFindings(_ context.Context, _ time.Time) (int64, error) {
	return f.findings, f.fErr
}
func (f *fakePruner) PruneEvidence(_ context.Context, _ time.Time) (int64, error) {
	return f.evidence, f.eErr
}
func (f *fakePruner) PruneRuns(_ context.Context, _ time.Time) (int64, error) {
	return f.runs, f.rErr
}

func TestEnforceHappy(t *testing.T) {
	t.Parallel()
	p := retention.Policy{FindingsDays: 90, EvidenceDays: 30, RunsDays: 180}
	pr := &fakePruner{findings: 3, evidence: 5, runs: 1}
	r, err := retention.Enforce(context.Background(), time.Now(), p, pr)
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if r.FindingsRemoved != 3 || r.EvidenceRemoved != 5 || r.RunsRemoved != 1 {
		t.Fatalf("report=%+v", r)
	}
}

func TestEnforceZeroDaysSkips(t *testing.T) {
	t.Parallel()
	p := retention.Policy{FindingsDays: 0, EvidenceDays: 0, RunsDays: 0}
	pr := &fakePruner{findings: 100, evidence: 100, runs: 100}
	r, err := retention.Enforce(context.Background(), time.Now(), p, pr)
	if err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if r.FindingsRemoved+r.EvidenceRemoved+r.RunsRemoved != 0 {
		t.Fatalf("expected no-op, got %+v", r)
	}
}

func TestEnforceRejectsAbsurdPolicy(t *testing.T) {
	t.Parallel()
	p := retention.Policy{FindingsDays: -1}
	_, err := retention.Enforce(context.Background(), time.Now(), p, &fakePruner{})
	if !errors.Is(err, retention.ErrInvalidPolicy) {
		t.Fatalf("got %v, want ErrInvalidPolicy", err)
	}
}

func TestCutoffMicroTruncated(t *testing.T) {
	t.Parallel()
	p := retention.Policy{FindingsDays: 7}
	now := time.Date(2026, 4, 19, 10, 0, 0, 123_456_789, time.UTC)
	c := p.Cutoff(now, retention.ClassFindings)
	if c.Nanosecond() != 123_456_000 {
		t.Fatalf("Cutoff not microsecond-truncated: ns=%d", c.Nanosecond())
	}
}
