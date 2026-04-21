package stream_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"local/elsereno/internal/audit"
	"local/elsereno/internal/web/stream"
)

func TestTailAudit_PublishesOnlyNewEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	// Pre-seed the file with an entry BEFORE the tailer starts;
	// it must not replay this one (fresh dashboard shouldn't see
	// yesterday's chain).
	preWriter, err := audit.OpenFileWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := preWriter.Append(context.Background(), audit.Entry{
		EventType: audit.EventGenesis,
		Actor:     "preboot",
	}); err != nil {
		t.Fatal(err)
	}
	_ = preWriter.Close()

	b := stream.New(8)
	ch, cancelSub := b.Subscribe()
	defer cancelSub()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- stream.TailAudit(ctx, b, path, 25*time.Millisecond) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	// Give the tailer a beat to seek to end.
	time.Sleep(75 * time.Millisecond)

	// Now append a fresh entry via a new writer. The tailer must
	// pick it up.
	writer, err := audit.OpenFileWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if _, err := writer.Append(context.Background(), audit.Entry{
		EventType: audit.EventVaultUnlock,
		Actor:     "operator",
		Payload:   json.RawMessage(`{"path":"/tmp/v"}`),
	}); err != nil {
		t.Fatal(err)
	}

	select {
	case ev := <-ch:
		if ev.Kind != stream.EventAudit {
			t.Fatalf("kind = %q", ev.Kind)
		}
		var got map[string]any
		if err := json.Unmarshal(ev.Payload, &got); err != nil {
			t.Fatal(err)
		}
		if got["event_type"] != string(audit.EventVaultUnlock) {
			t.Fatalf("event_type = %v, want %q", got["event_type"], audit.EventVaultUnlock)
		}
		if got["actor"] != "operator" {
			t.Fatalf("actor = %v", got["actor"])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("tailer never published the new entry")
	}

	// Confirm the tailer did NOT publish the pre-existing entry.
	select {
	case ev := <-ch:
		t.Fatalf("unexpected extra event: %+v", ev)
	case <-time.After(150 * time.Millisecond):
		// OK — no more events.
	}
}

func TestTailAudit_StopsOnCtxCancel(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	// Empty file so the tailer opens cleanly.
	// #nosec G306 -- test fixture
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	b := stream.New(4)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- stream.TailAudit(ctx, b, path, 20*time.Millisecond) }()
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err == nil || err.Error() != context.Canceled.Error() {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("tailer did not stop on ctx cancel")
	}
}

func TestTailAudit_NilBroadcasterRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	err := stream.TailAudit(context.Background(), nil, path, time.Millisecond)
	if err == nil {
		t.Fatal("expected error for nil broadcaster")
	}
}
