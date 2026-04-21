package stream

import (
	"encoding/json"
	"time"

	"local/elsereno/internal/core"
)

// PublishFinding fans a core.Finding out as an EventFinding on b.
// Safe to call with b == nil (no-op) so CLI paths that optionally
// wire a dashboard can keep a single code path.
func PublishFinding(b *Broadcaster, f core.Finding) {
	if b == nil {
		return
	}
	payload, err := json.Marshal(findingWirePayload{
		ID:        string(f.ID),
		RunID:     string(f.RunID),
		TargetID:  string(f.TargetID),
		Protocol:  f.Protocol,
		Severity:  string(f.Severity),
		Score:     f.Score,
		CreatedAt: f.CreatedAt,
		Factors:   f.Factors,
	})
	if err != nil {
		payload = []byte(`{}`)
	}
	b.Publish(Event{Kind: EventFinding, Payload: payload})
}

// PublishRunStart announces a scan run has started.
func PublishRunStart(b *Broadcaster, runID, operator string, startedAt time.Time) {
	if b == nil {
		return
	}
	payload, err := json.Marshal(runWirePayload{
		RunID:     runID,
		Operator:  operator,
		StartedAt: startedAt,
	})
	if err != nil {
		payload = []byte(`{}`)
	}
	b.Publish(Event{Kind: EventRunStart, Payload: payload})
}

// PublishRunEnd announces a scan run has finished. `status` is
// "completed" / "cancelled" / "error"; "counts" is the per-severity
// tally (keys "info" "low" "medium" "high" "critical").
func PublishRunEnd(b *Broadcaster, runID, status string, finishedAt time.Time, counts map[string]int) {
	if b == nil {
		return
	}
	payload, err := json.Marshal(runEndWirePayload{
		RunID:      runID,
		Status:     status,
		FinishedAt: finishedAt,
		Counts:     counts,
	})
	if err != nil {
		payload = []byte(`{}`)
	}
	b.Publish(Event{Kind: EventRunEnd, Payload: payload})
}

// findingWirePayload is the dashboard-facing projection of a core.Finding.
// Bytes / hashes are excluded; dashboards show the metadata, the DB
// persists the full record.
type findingWirePayload struct {
	ID        string         `json:"id"`
	RunID     string         `json:"run_id"`
	TargetID  string         `json:"target_id"`
	Protocol  string         `json:"protocol"`
	Severity  string         `json:"severity"`
	Score     int            `json:"score"`
	CreatedAt time.Time      `json:"created_at"`
	Factors   map[string]int `json:"factors,omitempty"`
}

type runWirePayload struct {
	RunID     string    `json:"run_id"`
	Operator  string    `json:"operator"`
	StartedAt time.Time `json:"started_at"`
}

type runEndWirePayload struct {
	RunID      string         `json:"run_id"`
	Status     string         `json:"status"`
	FinishedAt time.Time      `json:"finished_at"`
	Counts     map[string]int `json:"counts,omitempty"`
}
