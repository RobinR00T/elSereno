package stream_test

import (
	"encoding/json"
	"testing"
	"time"

	"local/elsereno/internal/core"
	"local/elsereno/internal/web/stream"
)

func TestPublishFinding_EncodesWireFields(t *testing.T) {
	b := stream.New(4)
	ch, cancel := b.Subscribe()
	defer cancel()

	f := core.Finding{
		ID:        core.UUID("11111111-1111-4111-8111-111111111111"),
		RunID:     core.UUID("22222222-2222-4222-8222-222222222222"),
		TargetID:  core.UUID("33333333-3333-4333-8333-333333333333"),
		Protocol:  "modbus",
		Severity:  core.SeverityHigh,
		Score:     77,
		CreatedAt: time.Date(2026, 4, 21, 0, 0, 0, 0, time.UTC),
		Factors:   map[string]int{"exposure": 80, "protocol_risk": 90},
	}
	stream.PublishFinding(b, f)

	select {
	case ev := <-ch:
		if ev.Kind != stream.EventFinding {
			t.Fatalf("kind = %q", ev.Kind)
		}
		var got map[string]any
		if err := json.Unmarshal(ev.Payload, &got); err != nil {
			t.Fatal(err)
		}
		if got["protocol"] != "modbus" {
			t.Fatalf("protocol = %v", got["protocol"])
		}
		if got["severity"] != "high" {
			t.Fatalf("severity = %v", got["severity"])
		}
		score, ok := got["score"].(float64)
		if !ok || score != 77 {
			t.Fatalf("score = %v", got["score"])
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("no event")
	}
}

func TestPublishRun_StartAndEnd(t *testing.T) {
	b := stream.New(4)
	ch, cancel := b.Subscribe()
	defer cancel()

	now := time.Now().UTC()
	stream.PublishRunStart(b, "run-1", "danielsolisagea", now)
	stream.PublishRunEnd(b, "run-1", "completed", now.Add(time.Second),
		map[string]int{"high": 3, "medium": 7})

	gotStart := <-ch
	gotEnd := <-ch
	if gotStart.Kind != stream.EventRunStart {
		t.Fatalf("start kind = %q", gotStart.Kind)
	}
	if gotEnd.Kind != stream.EventRunEnd {
		t.Fatalf("end kind = %q", gotEnd.Kind)
	}

	var start map[string]any
	if err := json.Unmarshal(gotStart.Payload, &start); err != nil {
		t.Fatal(err)
	}
	if start["run_id"] != "run-1" {
		t.Fatalf("start run_id = %v", start["run_id"])
	}

	var end map[string]any
	if err := json.Unmarshal(gotEnd.Payload, &end); err != nil {
		t.Fatal(err)
	}
	counts, ok := end["counts"].(map[string]any)
	if !ok {
		t.Fatalf("end counts missing or wrong type: %v", end["counts"])
	}
	high, ok := counts["high"].(float64)
	if !ok || high != 3 {
		t.Fatalf("end counts.high = %v", counts["high"])
	}
}

func TestPublishFinding_NilBroadcasterIsNoOp(_ *testing.T) {
	stream.PublishFinding(nil, core.Finding{})
	stream.PublishRunStart(nil, "x", "y", time.Now())
	stream.PublishRunEnd(nil, "x", "ok", time.Now(), nil)
	// Reaching here without panic is the assertion.
}
