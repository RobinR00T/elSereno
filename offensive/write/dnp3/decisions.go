//go:build offensive

package dnp3

import (
	"log"
	"sync"
)

// DecisionKind classifies what the gate did with a request it did not
// forward, plus the end-of-session summary.
type DecisionKind int

const (
	// DecisionRefused is a refusal answered with an IIN2.0 response.
	DecisionRefused DecisionKind = iota
	// DecisionRefusedSilent is a refusal without a reply, where an
	// outstation would not answer either (broadcast, NO-ACK request,
	// Confirm, UNS set, no application header).
	DecisionRefusedSilent
	// DecisionDiscarded is a frame dropped before judgement, because it failed
	// the AN2013-004b checks or the transport reassembly rules.
	DecisionDiscarded
	// DecisionSessionSummary carries the totals of a session, sent once
	// when the session ends (when Handle returns), and only if the
	// session refused or discarded something.
	DecisionSessionSummary
)

// String renders the kind for logs and audit payloads.
func (k DecisionKind) String() string {
	switch k {
	case DecisionRefused:
		return "refused"
	case DecisionRefusedSilent:
		return "refused_silent"
	case DecisionDiscarded:
		return "discarded"
	case DecisionSessionSummary:
		return "session_summary"
	default:
		return "unknown"
	}
}

// GateDecision is one record of the gate's decisions. For a refusal or
// a discard, Reason says why and Src, Dest and AppFC describe the
// request (AppFC is -1 when it had no application header; NoAddress is
// set when there was no valid link header to take Src and Dest from).
// A session summary carries the totals instead.
type GateDecision struct {
	Kind      DecisionKind
	Reason    string
	Src, Dest uint16
	AppFC     int
	NoAddress bool

	// Session summary only.
	Forwarded, Refused, RefusedSilent, Discarded int
	// Suppressed counts the refusals and discards past the per-session
	// burst that were counted but not reported one by one.
	Suppressed int
}

// decisionBurst is how many refusals and discards a session reports one
// by one; the master side decides how many there are, so the rest are
// only counted, and reported in the session summary.
const decisionBurst = 20

// decisionRecorder counts a session's decisions and reports them to the
// handler's OnDecision callback (stderr when none is set). The master
// side records from forward and the summary may come from Handle, so
// the counters are guarded and the summary is sent once.
type decisionRecorder struct {
	sink func(GateDecision)

	mu                                           sync.Mutex
	forwarded, refused, silent, discarded, shown int
	summarised                                   sync.Once
}

func newDecisionRecorder(h *WriteGatedHandler) *decisionRecorder {
	sink := h.OnDecision
	if sink == nil {
		sink = func(d GateDecision) {
			if d.Kind == DecisionSessionSummary {
				log.Printf("dnp3: gate session: forwarded=%d refused=%d refused_silent=%d discarded=%d suppressed=%d",
					d.Forwarded, d.Refused, d.RefusedSilent, d.Discarded, d.Suppressed)
				return
			}
			log.Printf("dnp3: gate %s src=%d dest=%d app_fc=%d: %s", d.Kind, d.Src, d.Dest, d.AppFC, d.Reason)
		}
	}
	return &decisionRecorder{sink: sink}
}

// forward counts a forwarded request or link frame; it is reported only
// in the summary.
func (r *decisionRecorder) forward() {
	r.mu.Lock()
	r.forwarded++
	r.mu.Unlock()
}

// record counts a refusal or a discard and reports it while the
// session is within its burst.
func (r *decisionRecorder) record(d GateDecision) {
	r.mu.Lock()
	switch d.Kind {
	case DecisionRefused:
		r.refused++
	case DecisionRefusedSilent:
		r.silent++
	default:
		r.discarded++
	}
	show := r.shown < decisionBurst
	if show {
		r.shown++
	}
	r.mu.Unlock()
	if show {
		r.sink(d)
	}
}

// summary reports the session totals once, and only for a session that
// refused or discarded something: a clean session records nothing, so
// opening connections that only forward adds nothing to the chain.
func (r *decisionRecorder) summary() {
	r.summarised.Do(func() {
		r.mu.Lock()
		d := GateDecision{
			Kind: DecisionSessionSummary, AppFC: -1, NoAddress: true,
			Forwarded: r.forwarded, Refused: r.refused, RefusedSilent: r.silent,
			Discarded: r.discarded, Suppressed: r.refused + r.silent + r.discarded - r.shown,
		}
		r.mu.Unlock()
		if d.Refused+d.RefusedSilent+d.Discarded > 0 {
			r.sink(d)
		}
	})
}

// appFCOf returns the application function code of a fragment, or -1
// when it has no application header.
func appFCOf(apdu []byte) int {
	if len(apdu) < 3 {
		return -1
	}
	return int(apdu[2])
}
