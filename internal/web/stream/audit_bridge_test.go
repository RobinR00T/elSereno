package stream_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"local/elsereno/internal/audit"
	"local/elsereno/internal/web/stream"
)

func TestAuditObserver_PublishesPerAppend(t *testing.T) {
	dir := t.TempDir()
	w, err := audit.OpenFileWriter(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })

	b := stream.New(8)
	ch, cancel := b.Subscribe()
	defer cancel()

	w.SetObserver(stream.AuditObserver(b))

	entry, err := w.Append(context.Background(), audit.Entry{
		EventType: audit.EventGenesis,
		Actor:     "ci",
		Payload:   json.RawMessage(`{"note":"boot"}`),
	})
	if err != nil {
		t.Fatal(err)
	}

	select {
	case ev := <-ch:
		if ev.Kind != stream.EventAudit {
			t.Fatalf("kind = %q, want %q", ev.Kind, stream.EventAudit)
		}
		var got map[string]any
		if err := json.Unmarshal(ev.Payload, &got); err != nil {
			t.Fatalf("payload not valid JSON: %v — raw=%q", err, ev.Payload)
		}
		id, ok := got["id"].(float64)
		if !ok || id != float64(entry.ID) {
			t.Fatalf("id mismatch — got %v, want %d", got["id"], entry.ID)
		}
		if got["event_type"] != string(audit.EventGenesis) {
			t.Fatalf("event_type = %v, want %q", got["event_type"], audit.EventGenesis)
		}
		if got["actor"] != "ci" {
			t.Fatalf("actor = %v", got["actor"])
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("no event received — observer not invoked")
	}
}

func TestAuditObserver_NilBroadcasterIsNoOp(_ *testing.T) {
	// Must not panic when b is nil.
	obs := stream.AuditObserver(nil)
	obs(audit.Entry{EventType: audit.EventGenesis})
}
