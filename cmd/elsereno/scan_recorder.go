//go:build !mini

package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"net/netip"
	"time"

	"local/elsereno/internal/core"
	"local/elsereno/internal/repo"
	"local/elsereno/internal/scanorch"
	"local/elsereno/internal/web/stream"
)

// dbRunRecorder writes runs, targets and findings to Postgres, where
// the dashboard and /api/v1/{runs,findings} read them, and announces
// them on the SSE stream.
type dbRunRecorder struct {
	w *repo.RunWriter
	b *stream.Broadcaster
}

func (d dbRunRecorder) Start(ctx context.Context, job scanorch.Job) (string, error) {
	id, err := d.w.StartRun(ctx, job.Operator)
	if err != nil {
		return "", err
	}
	stream.PublishRunStart(d.b, id, job.Operator, time.Now().UTC())
	return id, nil
}

func (d dbRunRecorder) Record(ctx context.Context, runID string, f core.Finding, t core.Target) error {
	// A probe already in flight when the job is cancelled still sent its
	// traffic: its finding is kept, as on the SSE-only path, within a
	// bound.
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	stored, err := d.w.RecordFinding(rctx, runID, f, t.Address, uint16(t.Port))
	if err != nil {
		return err
	}
	stream.PublishFindingAt(d.b, stored, targetString(t))
	return nil
}

func (d dbRunRecorder) Finish(ctx context.Context, runID, status string, counts map[string]int) {
	// The run is closed even when the job's context was cancelled,
	// within a bound so a hung database cannot hold the worker.
	fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := d.w.FinishRun(fctx, runID, status); err != nil {
		log.Printf("serve: %v", err)
	}
	stream.PublishRunEnd(d.b, runID, status, time.Now().UTC(), counts)
}

// streamRunRecorder is used without a database: findings reach the SSE
// stream (and the job's counters) but are not kept.
type streamRunRecorder struct {
	b *stream.Broadcaster
}

func (s streamRunRecorder) Start(_ context.Context, job scanorch.Job) (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("run id: %w", err)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	id := fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
	stream.PublishRunStart(s.b, id, job.Operator, time.Now().UTC())
	return id, nil
}

func (s streamRunRecorder) Record(_ context.Context, runID string, f core.Finding, t core.Target) error {
	f.RunID = core.UUID(runID)
	if f.CreatedAt.IsZero() {
		f.CreatedAt = time.Now().UTC()
	}
	stream.PublishFindingAt(s.b, f, targetString(t))
	return nil
}

// targetString is the address:port a finding was probed on.
func targetString(t core.Target) string {
	return netip.AddrPortFrom(t.Address, uint16(t.Port)).String()
}

func (s streamRunRecorder) Finish(_ context.Context, runID, status string, counts map[string]int) {
	stream.PublishRunEnd(s.b, runID, status, time.Now().UTC(), counts)
}
