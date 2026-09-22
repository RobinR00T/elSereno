//go:build offensive

package main

import (
	"context"
	"encoding/json"
	"log"

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
