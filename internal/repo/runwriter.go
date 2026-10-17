package repo

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"time"

	"local/elsereno/internal/core"
)

// RunWriter records a scan run and its findings in the runs, targets
// and findings tables that ListRuns, ListFindings, DiffFindings and
// Triage read. Until 2026-10-17 nothing wrote them, so the dashboard's
// runs and findings panels stayed empty whatever was scanned
// (PITF-094).
type RunWriter struct {
	q Querier
	// now is the clock; tests replace it.
	now func() time.Time
}

// NewRunWriter wraps the pool the dashboard reads from.
func NewRunWriter(q Querier) *RunWriter {
	return &RunWriter{q: q, now: time.Now}
}

// StartRun inserts a run in status "running" and returns its ID.
func (w *RunWriter) StartRun(ctx context.Context, operator string) (string, error) {
	id, err := newUUID()
	if err != nil {
		return "", err
	}
	if _, err := w.q.Exec(ctx,
		`INSERT INTO runs (id, started_at, status, operator) VALUES ($1, $2, 'running', $3)`,
		id, w.now().UTC(), operator); err != nil {
		return "", fmt.Errorf("repo: start run: %w", err)
	}
	return id, nil
}

// RecordFinding stores one finding of a run, against the target it was
// probed on (upserted by address and port), and returns it with the
// IDs and hash it was stored with. A finding without a hash gets the
// SHA-256 of protocol, address and port, so DiffFindings can match it
// across runs.
func (w *RunWriter) RecordFinding(ctx context.Context, runID string, f core.Finding, addr netip.Addr, port uint16) (core.Finding, error) {
	// INET has no zone ("fe80::1%en0" does not parse).
	addr = addr.WithZone("").Unmap()
	newTarget, err := newUUID()
	if err != nil {
		return f, err
	}
	var targetID string
	err = w.q.QueryRow(ctx, `
INSERT INTO targets (id, address, port) VALUES ($1, $2::inet, $3)
ON CONFLICT (address, port) DO UPDATE SET last_seen = NOW()
RETURNING id::text`, newTarget, addr.String(), int(port)).Scan(&targetID)
	if err != nil {
		return f, fmt.Errorf("repo: upsert target %s: %w", netip.AddrPortFrom(addr, port), err)
	}
	id, err := newUUID()
	if err != nil {
		return f, err
	}
	f.ID, f.RunID, f.TargetID = core.UUID(id), core.UUID(runID), core.UUID(targetID)
	if f.CreatedAt.IsZero() {
		f.CreatedAt = w.now().UTC()
	}
	if len(f.FindingHash) == 0 {
		sum := sha256.Sum256([]byte(f.Protocol + "|" + addr.String() + "|" + strconv.Itoa(int(port))))
		f.FindingHash = sum[:]
	}
	factors := f.Factors
	if factors == nil {
		factors = map[string]int{}
	}
	factorsJSON, err := json.Marshal(factors)
	if err != nil {
		return f, fmt.Errorf("repo: encode factors: %w", err)
	}
	if _, err := w.q.Exec(ctx, `
INSERT INTO findings (id, run_id, target_id, protocol, severity, score, finding_hash, created_at, factors)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		id, runID, targetID, f.Protocol, string(f.Severity), f.Score, f.FindingHash, f.CreatedAt, factorsJSON); err != nil {
		return f, fmt.Errorf("repo: insert finding: %w", err)
	}
	return f, nil
}

// FinishRun sets a run's final status and finish time.
func (w *RunWriter) FinishRun(ctx context.Context, runID, status string) error {
	if _, err := w.q.Exec(ctx,
		`UPDATE runs SET status = $2, finished_at = $3 WHERE id = $1`,
		runID, status, w.now().UTC()); err != nil {
		return fmt.Errorf("repo: finish run: %w", err)
	}
	return nil
}

// newUUID returns a random (version 4) UUID in its 8-4-4-4-12 form.
func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("repo: uuid: %w", err)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
