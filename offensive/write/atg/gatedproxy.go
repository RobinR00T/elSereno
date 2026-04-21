//go:build offensive

// Package atg hosts the ATG Veeder-Root write-gated proxy
// session-authorisation primitives. Commands authorised via a
// prefix-match table (V=setpoint, S=set-configuration, T=tank-
// calibration); v1.2 adds the full line-oriented relay.
package atg

import (
	"crypto/sha256"
	"sort"

	"local/elsereno/offensive/confirm"
)

// AllowedCommand scopes an ATG command prefix the operator
// authorises (single uppercase letter: 'V' for setpoint, 'S' for
// configuration-set, 'T' for tank calibration, etc.). 'I' info
// commands are always allowed and don't need to appear here.
type AllowedCommand struct {
	Prefix byte
}

// AllowlistHash returns the deterministic SHA-256 over target +
// sorted allowlist.
func AllowlistHash(target string, allowed []AllowedCommand) [32]byte {
	sorted := append([]AllowedCommand(nil), allowed...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Prefix < sorted[j].Prefix })
	h := sha256.New()
	_, _ = h.Write([]byte(target))
	_, _ = h.Write([]byte{0x00})
	for _, a := range sorted {
		_, _ = h.Write([]byte{a.Prefix})
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// SessionMutation builds the session-level confirm.Mutation.
func SessionMutation(target string, allowed []AllowedCommand) confirm.Mutation {
	return confirm.Mutation{
		Category:    confirm.CategoryWrite,
		Protocol:    "atg",
		Operation:   "proxy_session",
		Target:      target,
		PayloadHash: AllowlistHash(target, allowed),
	}
}
