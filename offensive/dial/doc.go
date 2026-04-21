//go:build offensive

// Package dial performs individual validation + batch
// wardialing against AT modems / VoIP endpoints. Requires
// `-tags offensive`. The ≤3-digit hard block applies
// unconditionally; additional blacklists come from
// `scope.yaml`'s `blocked_numbers`. The batch mode (v1.1
// chunk 8) classifies every number against the guard and
// appends one `offensive_dial` audit entry per decision, so
// an operator tailing the chain can reconstruct the whole
// wardial without keeping the original input file. Actual
// PSTN / VoIP delivery lands with v1.2 when the modem +
// backend integrations ship; for v1.1 the default
// disposition is "preview" (audit-only dry-run).
package dial
