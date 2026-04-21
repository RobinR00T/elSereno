package stream

import (
	"encoding/json"
	"time"

	"local/elsereno/internal/audit"
)

// AuditObserver returns an `audit.Observer` that publishes every
// appended audit entry onto b as an `EventAudit`. The payload is a
// compact JSON object with the operator-visible fields; `prev_hash`
// and `entry_hash` are omitted (dashboard shows a summary, not the
// raw chain).
//
// Callers typically do:
//
//	w, _ := audit.OpenFileWriter(path)
//	w.SetObserver(stream.AuditObserver(srv.Broadcaster()))
//
// so every CLI-side write → audit → dashboard fan-out happens
// without the offensive runtime knowing about the web layer.
func AuditObserver(b *Broadcaster) audit.Observer {
	if b == nil {
		return func(audit.Entry) {}
	}
	return func(e audit.Entry) {
		payload, err := json.Marshal(auditWirePayload{
			ID:         e.ID,
			EventType:  string(e.EventType),
			Actor:      e.Actor,
			OccurredAt: e.OccurredAt,
			Payload:    e.Payload,
		})
		if err != nil {
			// JSON marshal of a sane audit.Entry should never fail;
			// if it does, fall back to an empty payload so the
			// client still sees the ID + kind.
			payload = []byte(`{}`)
		}
		b.Publish(Event{
			Kind:    EventAudit,
			Payload: payload,
		})
	}
}

// auditWirePayload is the dashboard-facing projection of an
// audit.Entry. Intentionally flatter than the on-disk Entry so the
// UI can render without chasing the chain fields.
type auditWirePayload struct {
	ID         int64           `json:"id"`
	EventType  string          `json:"event_type"`
	Actor      string          `json:"actor"`
	OccurredAt time.Time       `json:"occurred_at"`
	Payload    json.RawMessage `json:"payload,omitempty"`
}
