//go:build offensive

// Package fox hosts the Niagara Fox write-gated proxy session-
// authorisation primitives. The Fox protocol is line-oriented
// administrative; v1.2 adds the full relay with per-command
// allowlisting (fox hello, fox session, fox auth, etc.).
package fox

import (
	"crypto/sha256"
	"sort"

	"local/elsereno/offensive/confirm"
)

// AllowedCommand scopes a Fox command verb the operator
// authorises (e.g. "hello", "session", "auth").
type AllowedCommand struct {
	Verb string
}

// AllowlistHash returns the deterministic SHA-256 over target +
// sorted allowlist.
func AllowlistHash(target string, allowed []AllowedCommand) [32]byte {
	sorted := append([]AllowedCommand(nil), allowed...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Verb < sorted[j].Verb })
	h := sha256.New()
	_, _ = h.Write([]byte(target))
	_, _ = h.Write([]byte{0x00})
	for _, a := range sorted {
		_, _ = h.Write([]byte(a.Verb))
		_, _ = h.Write([]byte{0x00})
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// SessionMutation builds the session-level confirm.Mutation.
func SessionMutation(target string, allowed []AllowedCommand) confirm.Mutation {
	return confirm.Mutation{
		Category:    confirm.CategoryWrite,
		Protocol:    "fox",
		Operation:   "proxy_session",
		Target:      target,
		PayloadHash: AllowlistHash(target, allowed),
	}
}
