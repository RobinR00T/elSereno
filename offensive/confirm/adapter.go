//go:build offensive

package confirm

import (
	"context"
	"encoding/json"
	"fmt"

	"local/elsereno/internal/audit"
)

// auditWriterAdapter implements Auditor by mapping confirm.AuditEvent
// records onto the underlying audit.Writer's chained-hash append
// stream. The existing audit schema enumerates event_types at the
// plugin-category granularity (offensive_write, offensive_dial,
// offensive_harvest); we collapse confirm.Category onto those and
// encode the disposition (allowed / denied / failed) inside the
// JSONB payload so receivers can split without a schema change.
type auditWriterAdapter struct {
	writer audit.Writer
	actor  string
}

// NewAuditor wires an audit.Writer into the confirm.Auditor
// surface. `actor` is the operator identifier (usually the OS
// user) that appears in every emitted row.
func NewAuditor(w audit.Writer, actor string) Auditor {
	return &auditWriterAdapter{writer: w, actor: actor}
}

// Record implements Auditor. Returns an error if the underlying
// append fails (typically a broken audit chain); Authorize
// propagates that up so the caller refuses to fire the mutation.
func (a *auditWriterAdapter) Record(ctx context.Context, ev AuditEvent) error {
	if a.writer == nil {
		return nil
	}
	event, err := categoryToAuditType(ev.Category)
	if err != nil {
		return err
	}
	payload := map[string]any{
		"disposition":  ev.EventType, // offensive_allowed|denied|failed|attempt
		"category":     string(ev.Category),
		"protocol":     ev.Protocol,
		"operation":    ev.Operation,
		"target":       ev.Target,
		"payload_hash": ev.PayloadHash,
	}
	if ev.Reason != "" {
		payload["reason"] = ev.Reason
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("confirm: audit marshal: %w", err)
	}
	_, err = a.writer.Append(ctx, audit.Entry{
		EventType: event,
		Actor:     a.actor,
		Payload:   body,
	})
	return err
}

// categoryToAuditType collapses confirm.Category onto the existing
// schema. CategoryExploit maps to offensive_write because the
// enum doesn't have a dedicated offensive_exploit row yet; a
// migration adds granular types in v1.2.
func categoryToAuditType(c Category) (audit.EventType, error) {
	switch c {
	case CategoryWrite, CategoryExploit:
		return audit.EventOffWrite, nil
	case CategoryDial:
		return audit.EventOffDial, nil
	case CategoryHarvest:
		return audit.EventOffHarvest, nil
	default:
		return "", fmt.Errorf("confirm: unmapped category %q", c)
	}
}
