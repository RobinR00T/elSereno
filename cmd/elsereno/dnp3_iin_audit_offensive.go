//go:build offensive

package main

import (
	"context"
	"encoding/json"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"local/elsereno/internal/audit"
	dnpwrite "local/elsereno/offensive/write/dnp3"
)

// dnp3IINObserver returns the OnIIN callback wired into the DNP3
// write-gated proxy. It logs each notable Internal Indications alert to
// stderr for immediacy and records it in the tamper-evident audit chain
// so the observation survives past the session and reaches the
// dashboard / SSE feed. Recording is best-effort: a broken audit write
// never disturbs the proxy's data path (the response was already
// forwarded before inspection).
func dnp3IINObserver(target string, rt *offensiveRuntime) func(dnpwrite.IINEvent) {
	return func(ev dnpwrite.IINEvent) {
		log.Printf("dnp3: IIN alert [%s] target=%s src=%d dest=%d iin=0x%02x%02x bits=%v",
			ev.Kind, target, ev.Src, ev.Dest, ev.IIN1, ev.IIN2, ev.Bits)
		emitDNP3IINAudit(rt, target, ev)
	}
}

// decisionAuditQueue bounds the gate decisions waiting to be written,
// and decisionAuditFlush how long Close waits for them.
const (
	decisionAuditQueue = 256
	decisionAuditFlush = 5 * time.Second
)

// decisionAudit writes the gate's decisions to the audit chain from one
// goroutine, so the gate never waits on the audit file (an append takes
// the writer's lock and re-reads the chain, which grows with it). The
// queue is bounded: when it is full, or after Close, a decision is
// dropped and counted, and the count rides on the next row written
// (dropped_before). Close flushes the queue; the runtime runs it before
// closing the audit writer.
type decisionAudit struct {
	rt      *offensiveRuntime
	ch      chan map[string]any
	done    chan struct{}
	dropped atomic.Int64

	mu     sync.Mutex
	closed bool
}

func newDecisionAudit(rt *offensiveRuntime) *decisionAudit {
	a := &decisionAudit{rt: rt, ch: make(chan map[string]any, decisionAuditQueue), done: make(chan struct{})}
	go a.run()
	rt.atClose(a.Close)
	return a
}

func (a *decisionAudit) enqueue(body map[string]any) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		log.Printf("dnp3: gate decision after the audit queue closed, not written to the chain: %v", body)
		return
	}
	select {
	case a.ch <- body:
	default:
		a.dropped.Add(1)
	}
}

func (a *decisionAudit) run() {
	defer close(a.done)
	for body := range a.ch {
		if n := a.dropped.Swap(0); n > 0 {
			body["dropped_before"] = n
		}
		emitDNP3Audit(a.rt, audit.EventDNP3GateDecision, body)
	}
	if n := a.dropped.Load(); n > 0 {
		log.Printf("dnp3: %d gate decisions were not written to the audit chain (queue full or closed)", n)
	}
}

// Close stops accepting decisions and waits until the queue is written,
// for at most decisionAuditFlush: each row costs one append, which grows
// with the chain, and a stop must not hang on it.
func (a *decisionAudit) Close() {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return
	}
	a.closed = true
	close(a.ch)
	a.mu.Unlock()
	select {
	case <-a.done:
	case <-time.After(decisionAuditFlush):
		log.Printf("dnp3: %d gate decisions still queued after %s; the audit file closes without them", len(a.ch), decisionAuditFlush)
	}
}

// dnp3GateDecisionObserver returns the OnDecision callback wired into
// the DNP3 write-gated proxy: each refusal or discard it reports (the
// first ones of a session) and the session summary go to stderr and,
// through a bounded queue, to the audit chain as a dnp3_gate_decision
// row. Best-effort, like the IIN observer: the gate never blocks on it
// and a failed append never disturbs the proxy.
func dnp3GateDecisionObserver(target string, rt *offensiveRuntime) func(dnpwrite.GateDecision) {
	q := newDecisionAudit(rt)
	return func(d dnpwrite.GateDecision) {
		body := map[string]any{"kind": d.Kind.String(), "protocol": "dnp3", "target": target}
		if d.Kind == dnpwrite.DecisionSessionSummary {
			log.Printf("dnp3: gate session target=%s forwarded=%d refused=%d refused_silent=%d discarded=%d suppressed=%d",
				target, d.Forwarded, d.Refused, d.RefusedSilent, d.Discarded, d.Suppressed)
			body["forwarded"], body["refused"], body["refused_silent"] = d.Forwarded, d.Refused, d.RefusedSilent
			body["discarded"], body["suppressed"] = d.Discarded, d.Suppressed
		} else {
			log.Printf("dnp3: gate %s target=%s src=%d dest=%d app_fc=%d: %s", d.Kind, target, d.Src, d.Dest, d.AppFC, d.Reason)
			body["reason"], body["app_fc"] = d.Reason, d.AppFC
			if !d.NoAddress {
				body["src"], body["dest"] = d.Src, d.Dest
			}
		}
		q.enqueue(body)
	}
}

// emitDNP3Audit appends one row of the given event type. Best-effort.
func emitDNP3Audit(rt *offensiveRuntime, ev audit.EventType, body map[string]any) {
	if rt == nil || rt.Writer == nil {
		return
	}
	payload, err := json.Marshal(body)
	if err != nil {
		payload = []byte(`{"kind":"unknown","error":"audit_payload_marshal_failed"}`)
	}
	_, _ = rt.Writer.Append(context.Background(), audit.Entry{EventType: ev, Actor: rt.Actor, Payload: payload})
}

// emitDNP3IINAudit writes one dnp3_iin_alert row. Best-effort, mirroring
// the other proxy-observer audit emitters (cwmp_firmware_verify,
// proxy_allowlist_reload): a failed append does not propagate.
func emitDNP3IINAudit(rt *offensiveRuntime, target string, ev dnpwrite.IINEvent) {
	if rt == nil || rt.Writer == nil {
		return
	}
	body := map[string]any{
		"kind":     ev.Kind.String(),
		"protocol": "dnp3",
		"target":   target,
		"src":      ev.Src,
		"dest":     ev.Dest,
		"iin1":     ev.IIN1,
		"iin2":     ev.IIN2,
		"bits":     ev.Bits,
	}
	if ev.Kind == dnpwrite.IINErrorBurstKind {
		body["error_run"] = ev.ErrorRun
	}
	payload, err := json.Marshal(body)
	if err != nil {
		payload = []byte(`{"kind":"unknown","error":"audit_payload_marshal_failed"}`)
	}
	_, _ = rt.Writer.Append(context.Background(), audit.Entry{
		EventType: audit.EventDNP3IINAlert,
		Actor:     rt.Actor,
		Payload:   payload,
	})
}
