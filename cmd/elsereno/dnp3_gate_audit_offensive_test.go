//go:build offensive

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"local/elsereno/internal/audit"
	dnpwrite "local/elsereno/offensive/write/dnp3"
)

type recordingWriter struct{ entries []audit.Entry }

func (w *recordingWriter) Append(_ context.Context, e audit.Entry) (audit.Entry, error) {
	w.entries = append(w.entries, e)
	return e, nil
}

// TestDNP3GateDecisionObserverAudits: each decision and the summary land
// in the audit chain as dnp3_gate_decision rows with the documented
// payload.
func TestDNP3GateDecisionObserverAudits(t *testing.T) {
	w := &recordingWriter{}
	rt := &offensiveRuntime{Writer: w, Actor: "tester"}
	obs := dnp3GateDecisionObserver("10.0.0.5:20000", rt)
	obs(dnpwrite.GateDecision{Kind: dnpwrite.DecisionRefused, Reason: "application function not allowed (--dnp3-app-fc)", Src: 2, Dest: 1, AppFC: 0x0D})
	obs(dnpwrite.GateDecision{Kind: dnpwrite.DecisionSessionSummary, AppFC: -1, NoAddress: true, Forwarded: 3, Refused: 1})
	obs(dnpwrite.GateDecision{Kind: dnpwrite.DecisionDiscarded, Reason: "7 octets before a valid link header", AppFC: -1, NoAddress: true})
	rt.Close() // flushes the queue before the writer would close
	if len(w.entries) != 3 {
		t.Fatalf("got %d audit rows, want 3", len(w.entries))
	}
	for _, e := range w.entries {
		if e.EventType != audit.EventDNP3GateDecision || e.Actor != "tester" {
			t.Fatalf("row %+v", e)
		}
	}
	var dec, sum map[string]any
	if err := json.Unmarshal(w.entries[0].Payload, &dec); err != nil {
		t.Fatal(err)
	}
	if dec["kind"] != "refused" || dec["reason"] != "application function not allowed (--dnp3-app-fc)" || dec["app_fc"] != float64(0x0D) || dec["target"] != "10.0.0.5:20000" {
		t.Fatalf("decision payload %v", dec)
	}
	if err := json.Unmarshal(w.entries[1].Payload, &sum); err != nil {
		t.Fatal(err)
	}
	if sum["kind"] != "session_summary" || sum["forwarded"] != float64(3) || sum["refused"] != float64(1) || sum["suppressed"] != float64(0) {
		t.Fatalf("summary payload %v", sum)
	}
	var noAddr map[string]any
	if err := json.Unmarshal(w.entries[2].Payload, &noAddr); err != nil {
		t.Fatal(err)
	}
	if _, has := noAddr["src"]; has {
		t.Fatalf("a discard without a link header carries src: %v", noAddr)
	}
}

// blockingWriter holds its first Append until released; started is
// closed when that first Append begins. Only the queue's goroutine
// calls Append, so the counter needs no lock.
type blockingWriter struct {
	recordingWriter
	started, release chan struct{}
	calls            int
}

func (w *blockingWriter) Append(ctx context.Context, e audit.Entry) (audit.Entry, error) {
	w.calls++
	if w.calls == 1 {
		close(w.started)
		<-w.release
	}
	return w.recordingWriter.Append(ctx, e)
}

// TestDNP3GateDecisionQueueBounded: the gate never waits on the audit
// file. With the writer stuck, decisions past the queue are dropped and
// counted, the count rides on the next row written, and Close flushes
// the rest.
func TestDNP3GateDecisionQueueBounded(t *testing.T) {
	w := &blockingWriter{started: make(chan struct{}), release: make(chan struct{})}
	rt := &offensiveRuntime{Writer: w, Actor: "tester"}
	obs := dnp3GateDecisionObserver("10.0.0.5:20000", rt)
	d := dnpwrite.GateDecision{Kind: dnpwrite.DecisionRefused, Reason: "x", AppFC: 5}
	obs(d) // taken by the writer goroutine, which then blocks
	<-w.started
	for i := 0; i < decisionAuditQueue+3; i++ {
		obs(d) // never blocks: the last 3 do not fit
	}
	close(w.release)
	rt.Close()
	if got := len(w.entries); got != decisionAuditQueue+1 {
		t.Fatalf("wrote %d rows, want %d", got, decisionAuditQueue+1)
	}
	var second map[string]any
	if err := json.Unmarshal(w.entries[1].Payload, &second); err != nil {
		t.Fatal(err)
	}
	if second["dropped_before"] != float64(3) {
		t.Fatalf("second row %v, want dropped_before 3", second)
	}
	obs(d) // after Close: dropped, no panic
}

// TestDNP3GateDecisionFlushedBeforeFileCloses: with the real file
// writer, the queued rows are on disk once the runtime closes, because
// the queue flushes before the writer closes.
func TestDNP3GateDecisionFlushedBeforeFileCloses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	fw, err := audit.OpenFileWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	rt := &offensiveRuntime{Writer: fw, Actor: "tester"}
	obs := dnp3GateDecisionObserver("10.0.0.5:20000", rt)
	for i := 0; i < 5; i++ {
		obs(dnpwrite.GateDecision{Kind: dnpwrite.DecisionRefused, Reason: "x", AppFC: 5})
	}
	rt.Close()
	b, err := os.ReadFile(path) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(b), "dnp3_gate_decision"); n != 5 {
		t.Fatalf("%d dnp3_gate_decision rows on disk, want 5", n)
	}
}
