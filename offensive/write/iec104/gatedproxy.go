//go:build offensive

// Package iec104 hosts the IEC 60870-5-104 write-gated proxy
// session-authorisation primitives. Per-ASDU-Type-ID filtering
// lands with the full WriteGatedHandler in the v1.2 chunk that
// adds the ASDU parser; v1.1 ships the authorisation surface.
package iec104

import (
	"crypto/sha256"
	"sort"

	"local/elsereno/offensive/confirm"
)

// AllowedASDU scopes an IEC 104 ASDU type identifier the operator
// authorises for the session (common write type-IDs: 45 single
// command C_SC_NA_1, 46 double command C_DC_NA_1, 48 setpoint
// command C_SE_NA_1, 100 interrogation C_IC_NA_1, etc.).
type AllowedASDU struct {
	TypeID uint8
}

// AllowlistHash returns the deterministic SHA-256 over target +
// sorted allowlist.
func AllowlistHash(target string, allowed []AllowedASDU) [32]byte {
	sorted := append([]AllowedASDU(nil), allowed...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].TypeID < sorted[j].TypeID })
	h := sha256.New()
	_, _ = h.Write([]byte(target))
	_, _ = h.Write([]byte{0x00})
	for _, a := range sorted {
		_, _ = h.Write([]byte{a.TypeID})
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// SessionMutation builds the session-level confirm.Mutation.
func SessionMutation(target string, allowed []AllowedASDU) confirm.Mutation {
	return confirm.Mutation{
		Category:    confirm.CategoryWrite,
		Protocol:    "iec104",
		Operation:   "proxy_session",
		Target:      target,
		PayloadHash: AllowlistHash(target, allowed),
	}
}
