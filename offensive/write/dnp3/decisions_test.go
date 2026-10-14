//go:build offensive

package dnp3

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"local/elsereno/internal/protocols/dnp3/wire"
)

// TestGateDecisionsRecorded: every refusal and discard reaches
// OnDecision with its reason, and the session ends with one summary of
// the totals. Until 2026-10-14 a refusal left no trace beyond the reply
// and a discard only a stderr line.
func TestGateDecisionsRecorded(t *testing.T) {
	t.Parallel()
	var got []GateDecision
	h := latchOnlyGate()
	h.OnDecision = func(d GateDecision) { got = append(got, d) }

	read := userFrame([]byte{wire.TransportFIR | wire.TransportFIN, 0xC0, AppFCRead, 60, 1, 0x06})
	trip := userFrame(append([]byte{wire.TransportFIR | wire.TransportFIN, 0xC0, AppFCDirectOperate}, crobObjects(7, 0x81)...))
	bcast := ctrlFrame(0xC4, 0xFFFF, append([]byte{wire.TransportFIR | wire.TransportFIN, 0xC0, AppFCDirectOperate}, crobObjects(7, 0x81)...))
	badBlock := userFrame([]byte{wire.TransportFIR | wire.TransportFIN, 0xC0, AppFCRead, 60, 1, 0x06})
	badBlock[len(badBlock)-1] ^= 0x01
	runForward(t, h, cat(read, trip, bcast, badBlock))

	if len(got) != 4 {
		t.Fatalf("got %d decisions, want 3 and a summary: %+v", len(got), got)
	}
	want := []struct {
		kind   DecisionKind
		reason string
	}{
		{DecisionRefused, "control object outside the scope (--dnp3-control / --dnp3-analog)"},
		{DecisionRefusedSilent, "control or write to a broadcast address"},
		{DecisionDiscarded, "dnp3: invalid link frame (AN2013-004b): bad block CRC"},
	}
	for i, w := range want {
		if got[i].Kind != w.kind || got[i].Reason != w.reason {
			t.Errorf("decision %d: %s %q, want %s %q", i, got[i].Kind, got[i].Reason, w.kind, w.reason)
		}
	}
	if got[0].AppFC != int(AppFCDirectOperate) || got[0].Src != 2 || got[0].Dest != 1 {
		t.Errorf("refusal: app_fc %d src %d dest %d", got[0].AppFC, got[0].Src, got[0].Dest)
	}
	s := got[3]
	if s.Kind != DecisionSessionSummary || s.Forwarded != 1 || s.Refused != 1 || s.RefusedSilent != 1 || s.Discarded != 1 || s.Suppressed != 0 {
		t.Fatalf("summary %+v, want forwarded 1, refused 1, refused_silent 1, discarded 1, suppressed 0", s)
	}
}

// TestGateDecisionsBurst: the master side decides how many requests the
// gate refuses, so only the first decisionBurst are reported one by
// one; the rest are counted in the summary.
func TestGateDecisionsBurst(t *testing.T) {
	t.Parallel()
	var got []GateDecision
	h := latchOnlyGate()
	h.OnDecision = func(d GateDecision) { got = append(got, d) }
	trip := userFrame(append([]byte{wire.TransportFIR | wire.TransportFIN, 0xC0, AppFCDirectOperate}, crobObjects(7, 0x81)...))
	var in []byte
	for i := 0; i < decisionBurst+5; i++ {
		in = append(in, trip...)
	}
	runForward(t, h, in)
	if len(got) != decisionBurst+1 {
		t.Fatalf("got %d reports, want %d decisions and a summary", len(got), decisionBurst)
	}
	if s := got[decisionBurst]; s.Kind != DecisionSessionSummary || s.Refused != decisionBurst+5 || s.Suppressed != 5 {
		t.Fatalf("summary %+v, want refused %d, suppressed 5", s, decisionBurst+5)
	}
}

// TestGateDecisionsQuietSession: a session that refused and discarded
// nothing records nothing, not even a summary, so opening connections
// that only forward adds nothing to the chain.
func TestGateDecisionsQuietSession(t *testing.T) {
	t.Parallel()
	called := false
	h := latchOnlyGate()
	h.OnDecision = func(GateDecision) { called = true }
	read := userFrame([]byte{wire.TransportFIR | wire.TransportFIN, 0xC0, AppFCRead, 60, 1, 0x06})
	runForward(t, h, cat(read, wire.BuildRequestLinkStatus(1, 2)))
	if called {
		t.Fatal("a session that only forwarded reported a decision")
	}
}

// TestGateDecisionsEveryPath: each way of not forwarding reaches the
// record once, with what identifies it, and link frames count as
// forwarded.
func TestGateDecisionsEveryPath(t *testing.T) {
	t.Parallel()
	doFirst := userFrame(append([]byte{wire.TransportFIR, 0xC0, AppFCDirectOperate}, crobObjects(5, wire.OpLatchOn)...))
	doLast := userFrame(append([]byte{wire.TransportFIN | 1}, crobObjects(6, wire.OpLatchOn)...))
	readFirst := userFrame([]byte{wire.TransportFIR, 0xC0, AppFCRead, 60, 1, 0x06})
	orphan := userFrame([]byte{wire.TransportFIN | 1, 60, 2, 0x06})
	single := userFrame(append([]byte{wire.TransportFIR | wire.TransportFIN, 0xC0, AppFCDirectOperate}, crobObjects(6, wire.OpLatchOn)...))
	for name, tc := range map[string]struct {
		in        []byte
		kind      DecisionKind
		reason    string
		appFC     int
		noAddress bool
		forwarded int
	}{
		"octets before a header": {append([]byte{0xFF, 0xEE}, wire.BuildRequestLinkStatus(1, 2)...), DecisionDiscarded, "2 octets before a valid link header", -1, true, 1},
		"orphan continuation":    {orphan, DecisionDiscarded, "a continuation segment without a first segment", -1, false, 0},
		"held request dropped":   {cat(readFirst, single), DecisionDiscarded, "a new first segment dropped an incomplete multi-segment request", int(AppFCRead), false, 1},
		"garbage at the end":     {append(wire.BuildRequestLinkStatus(1, 2), 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44), DecisionDiscarded, "3 octets before a valid link header", -1, true, 1},

		"multi-segment control":    {cat(doFirst, doLast), DecisionRefused, "only a Read may span several transport segments", int(AppFCDirectOperate), false, 0},
		"session ends mid-request": {readFirst, DecisionDiscarded, "the session ended inside a multi-segment request", int(AppFCRead), false, 0},
	} {
		var got []GateDecision
		h := latchOnlyGate()
		h.OnDecision = func(d GateDecision) { got = append(got, d) }
		runForward(t, h, tc.in)
		if len(got) != 2 {
			t.Errorf("%s: %d reports %+v, want a decision and a summary", name, len(got), got)
			continue
		}
		d, s := got[0], got[1]
		if d.Kind != tc.kind || d.Reason != tc.reason || d.AppFC != tc.appFC || d.NoAddress != tc.noAddress {
			t.Errorf("%s: %s %q app_fc %d no_address %v", name, d.Kind, d.Reason, d.AppFC, d.NoAddress)
		}
		if s.Kind != DecisionSessionSummary || s.Forwarded != tc.forwarded {
			t.Errorf("%s: summary %+v, want forwarded %d", name, s, tc.forwarded)
		}
	}
}

// failingWriter fails every write.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

// TestGateDecisionRecordedWhenReplyFails: a refusal whose reply cannot
// be written is still recorded.
func TestGateDecisionRecordedWhenReplyFails(t *testing.T) {
	t.Parallel()
	var got []GateDecision
	h := latchOnlyGate()
	h.OnDecision = func(d GateDecision) { got = append(got, d) }
	trip := userFrame(append([]byte{wire.TransportFIR | wire.TransportFIN, 0xC0, AppFCDirectOperate}, crobObjects(7, 0x81)...))
	var up bytes.Buffer
	if err := h.forward(bytes.NewReader(trip), &up, failingWriter{}); err == nil {
		t.Fatal("forward did not report the failed reply")
	}
	if len(got) != 2 || got[0].Kind != DecisionRefused || got[1].Refused != 1 {
		t.Fatalf("got %+v, want the refusal and a summary", got)
	}
}

// TestGateDecisionSummaryWhenHandleEnds: when the session's context is
// cancelled, Handle returns while the master-side goroutine is still
// blocked in a read; the summary still comes, from Handle.
func TestGateDecisionSummaryWhenHandleEnds(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var got []GateDecision
	h := latchOnlyGate()
	h.authorised = true
	h.OnDecision = func(d GateDecision) {
		mu.Lock()
		got = append(got, d)
		mu.Unlock()
	}
	client, clientSide := net.Pipe()
	upstream, upstreamSide := net.Pipe()
	defer func() { _ = client.Close(); _ = clientSide.Close(); _ = upstream.Close(); _ = upstreamSide.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.Handle(ctx, clientSide, upstreamSide) }()
	trip := userFrame(append([]byte{wire.TransportFIR | wire.TransportFIN, 0xC0, AppFCDirectOperate}, crobObjects(7, 0x81)...))
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := client.Write(trip); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Read(make([]byte, 64)); err != nil { // the refusal
		t.Fatal(err)
	}
	cancel()
	<-done
	mu.Lock()
	defer mu.Unlock()
	if n := len(got); n < 2 || got[n-1].Kind != DecisionSessionSummary || got[n-1].Refused != 1 {
		t.Fatalf("after Handle returned: %+v, want the refusal then a summary", got)
	}
}

// TestDecisionRecorderConcurrent: forward's goroutine records while
// Handle's summary may run; the counters are guarded (run with -race).
func TestDecisionRecorderConcurrent(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var summaries int
	r := newDecisionRecorder(&WriteGatedHandler{OnDecision: func(d GateDecision) {
		if d.Kind == DecisionSessionSummary {
			mu.Lock()
			summaries++
			mu.Unlock()
		}
	}})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				r.forward()
				r.record(GateDecision{Kind: DecisionRefused, AppFC: 5})
				r.summary()
			}
		}()
	}
	wg.Wait()
	r.summary()
	if summaries != 1 {
		t.Fatalf("%d summaries, want exactly one", summaries)
	}
}
