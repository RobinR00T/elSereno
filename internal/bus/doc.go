// Package bus will carry typed events between producers and subscribers.
//
// Not built: this package has no code yet. Today serve inserts each
// finding with one INSERT (internal/repo/runwriter.go) and audit
// entries go to the JSONL file. The design below is ADR-008.
//
// Planned subscribers:
//   - findings-persistence (pgx.CopyFrom batched, 1000 findings or 1s).
//   - audit-persistence   (sequential INSERT, single goroutine).
//   - scoring, triage, web-sse, outbox.
//
// Findings are batched; audit is strictly sequential because the hash
// chain is not parallelisable (ADR-008).
package bus
