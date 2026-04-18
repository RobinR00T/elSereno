package core

import (
	"net/netip"
	"time"
)

// Target is an (address, port) tuple identifying a scan target.
type Target struct {
	Address netip.Addr
	Port    Port
	ASN     int
	Country string // ISO 3166-1 alpha-2 when known; "" otherwise.
}

// Run is a single execution of ElSereno with a scope and input set.
type Run struct {
	ID         UUID
	StartedAt  time.Time
	FinishedAt *time.Time
	Status     string
	ScopeHash  []byte
	Operator   string
}

// Finding is a scored observation produced by a protocol plugin.
type Finding struct {
	ID          UUID
	RunID       UUID
	TargetID    UUID
	Protocol    string
	Severity    Severity
	Score       int
	FindingHash []byte
	CreatedAt   time.Time
	Factors     map[string]int // per-factor sub-scores in [0,100].
}

// Evidence captures raw bytes associated with a Finding. Truncation
// follows evidence.max_payload_bytes; when truncated, OriginalSHA256 is
// populated with the SHA-256 of the full body.
type Evidence struct {
	ID               UUID
	FindingID        UUID
	Payload          []byte
	PayloadTruncated bool
	OriginalSize     int
	OriginalSHA256   []byte
	CapturedAt       time.Time
}

// Session is a stateful interaction (REPL, proxy) with a target.
type Session struct {
	ID         UUID
	RunID      UUID
	TargetID   UUID
	Protocol   string
	StartedAt  time.Time
	EndedAt    *time.Time
	Transcript []byte // JSONB; encoder lives in the adapter.
}
