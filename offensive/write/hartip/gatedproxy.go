//go:build offensive

// Package hartip hosts the HART-IP write-gated proxy session-
// authorisation primitives. Per-HART-command filtering lands with
// the v1.2 parser chunk; v1.1 ships the authorisation surface.
package hartip

import (
	"crypto/sha256"
	"sort"

	"local/elsereno/offensive/confirm"
)

// AllowedCommand scopes a HART command the operator authorises
// (HART Cmd 1 Read Primary Variable, 40 Enter/Exit Fixed Current
// Mode, 45 Calibrate, etc.).
type AllowedCommand struct {
	HARTCmd uint8
}

// AllowlistHash returns the deterministic SHA-256 over target +
// sorted allowlist.
func AllowlistHash(target string, allowed []AllowedCommand) [32]byte {
	sorted := append([]AllowedCommand(nil), allowed...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].HARTCmd < sorted[j].HARTCmd })
	h := sha256.New()
	_, _ = h.Write([]byte(target))
	_, _ = h.Write([]byte{0x00})
	for _, a := range sorted {
		_, _ = h.Write([]byte{a.HARTCmd})
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// SessionMutation builds the session-level confirm.Mutation.
func SessionMutation(target string, allowed []AllowedCommand) confirm.Mutation {
	return confirm.Mutation{
		Category:    confirm.CategoryWrite,
		Protocol:    "hartip",
		Operation:   "proxy_session",
		Target:      target,
		PayloadHash: AllowlistHash(target, allowed),
	}
}
