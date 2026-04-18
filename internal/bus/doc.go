// Package bus carries typed events between producers and subscribers.
//
// Subscribers:
//   - findings-persistence (pgx.CopyFrom batched, 1000 findings or 1s).
//   - audit-persistence   (sequential INSERT, single goroutine).
//   - scoring, triage, web-sse, outbox.
//
// Findings are batched; audit is strictly sequential because the hash
// chain is not parallelisable (ADR-008).
package bus
