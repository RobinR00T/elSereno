package auth

import "strings"

// Role enumerates the v2.38+ access tiers. Strictly ordered:
// admin > operator > viewer. A role check passes when the
// token-bound role is ≥ the required role.
type Role int

// Role constants. Negative-rank UnknownRole sorts below
// everything; explicit guards still recommended in callers.
const (
	RoleUnknown Role = iota
	RoleViewer
	RoleOperator
	RoleAdmin
)

// String renders the role for log/error display.
func (r Role) String() string {
	switch r {
	case RoleAdmin:
		return "admin"
	case RoleOperator:
		return "operator"
	case RoleViewer:
		return "viewer"
	default:
		return "unknown"
	}
}

// ParseRole maps a claim string to a Role. Case-insensitive +
// trims whitespace. Unknown strings yield RoleUnknown.
//
// Common synonyms accepted:
//   - "admin" / "administrator" / "elsereno-admin"
//   - "operator" / "scanner" / "elsereno-operator"
//   - "viewer" / "readonly" / "reader" / "elsereno-viewer"
//
// The synonyms come from observing common IdP group naming
// patterns (Okta + Auth0 + Azure AD); operators can also
// preprocess claims in their IdP rule layer if their naming
// doesn't match.
func ParseRole(s string) Role {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "admin", "administrator", "elsereno-admin", "root":
		return RoleAdmin
	case "operator", "scanner", "elsereno-operator", "scan-operator":
		return RoleOperator
	case "viewer", "readonly", "reader", "elsereno-viewer", "read-only":
		return RoleViewer
	}
	return RoleUnknown
}

// HighestRoleFromClaims walks all role/group-like claims and
// returns the highest rank. Inputs accepted:
//   - claim is a string → parse directly.
//   - claim is a []string → parse each, return max.
//   - claim is a []any (after JSON decode) → flatten + parse.
//   - anything else → RoleUnknown.
func HighestRoleFromClaims(roles []string) Role {
	best := RoleUnknown
	for _, r := range roles {
		if got := ParseRole(r); got > best {
			best = got
		}
	}
	return best
}

// Implies reports whether having role `have` satisfies the
// requirement for `want`. Strict numeric comparison.
func (r Role) Implies(want Role) bool {
	return r >= want
}
