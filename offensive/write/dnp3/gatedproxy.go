//go:build offensive

// Package dnp3 hosts the DNP3 write-gated proxy handler. Real
// byte-level forwarding lands with the full WriteGatedHandler in
// the v1.2 chunk that adds application-layer ASDU classification;
// v1.1 ships the session authorisation primitives so the CLI
// surface can already mint a dry-run token.
package dnp3

import (
	"crypto/sha256"
	"sort"

	"local/elsereno/offensive/confirm"
)

// AllowedControl scopes DNP3 link-layer primary function codes.
// Application-layer function codes (Read Class 0, Write, Direct
// Operate, Cold Restart, etc.) need the inner DNP3-APDU parser
// which is the v1.2 expansion.
type AllowedControl struct {
	// PrimaryFC is the link-layer primary function (0 Reset Link,
	// 1 Test Link, 3 Confirmed Data, 4 Unconfirmed Data, 9 Request
	// Link Status).
	PrimaryFC uint8
}

// AllowlistHash returns the deterministic SHA-256 over target +
// sorted allowlist.
func AllowlistHash(target string, allowed []AllowedControl) [32]byte {
	sorted := append([]AllowedControl(nil), allowed...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].PrimaryFC < sorted[j].PrimaryFC })
	h := sha256.New()
	_, _ = h.Write([]byte(target))
	_, _ = h.Write([]byte{0x00})
	for _, a := range sorted {
		_, _ = h.Write([]byte{a.PrimaryFC})
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// SessionMutation builds the session-level confirm.Mutation.
func SessionMutation(target string, allowed []AllowedControl) confirm.Mutation {
	return confirm.Mutation{
		Category:    confirm.CategoryWrite,
		Protocol:    "dnp3",
		Operation:   "proxy_session",
		Target:      target,
		PayloadHash: AllowlistHash(target, allowed),
	}
}
