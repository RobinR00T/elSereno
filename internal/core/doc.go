// Package core is the domain layer of ElSereno.
//
// It depends only on the Go standard library. Adapters (db, web,
// protocols, inputs, outputs, telemetry) depend on core; core never
// depends on them. See .context/architecture.md.
//
// Sentinel errors that belong to the domain live in this package
// (errors.go). Package-specific sentinels live in the emitting package —
// ErrChainBroken in internal/audit, ErrUnknownConfigField in
// internal/config.
package core
