//go:build offensive

package bacnet

import (
	"crypto/sha256"
	"sort"

	"local/elsereno/offensive/confirm"
)

// AllowedService scopes a BACnet confirmed-service choice the
// operator authorises for the session (e.g. 0x0F WriteProperty).
// Session authorisation is the same pattern as the TCP plugins;
// the actual UDP relay ships in the BACnet offensive relay (a
// follow-up because BACnet is UDP-only and the generic TCP proxy
// framework doesn't apply).
type AllowedService struct {
	ServiceChoice uint8
}

// AllowlistHash returns the deterministic SHA-256 over target +
// sorted allowlist.
func AllowlistHash(target string, allowed []AllowedService) [32]byte {
	sorted := append([]AllowedService(nil), allowed...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ServiceChoice < sorted[j].ServiceChoice })
	h := sha256.New()
	_, _ = h.Write([]byte(target))
	_, _ = h.Write([]byte{0x00})
	for _, a := range sorted {
		_, _ = h.Write([]byte{a.ServiceChoice})
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// SessionMutation builds the session-level confirm.Mutation.
func SessionMutation(target string, allowed []AllowedService) confirm.Mutation {
	return confirm.Mutation{
		Category:    confirm.CategoryWrite,
		Protocol:    "bacnet",
		Operation:   "proxy_session",
		Target:      target,
		PayloadHash: AllowlistHash(target, allowed),
	}
}
