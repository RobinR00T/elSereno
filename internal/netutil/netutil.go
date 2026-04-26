// Package netutil provides small, dependency-free helpers for
// IPv4 + IPv6 host:port string handling. The codebase already
// uses `net/netip` for the Addr-typed paths (resolve.go,
// dedupe.go, scope.go, every protocol probe); netutil collects
// the string-shape helpers that aren't covered by netip itself.
//
// Introduced in v1.14 chunk 1 as the foundation of the IPv6
// cross-cutting cycle (operator-requested 2026-04-25). Existing
// loopback-detection logic in cmd_serve.go was substring-based
// and missed IPv6 longform (`[0:0:0:0:0:0:0:1]:port`) + zone
// specifiers (`[::1%lo0]:port`). This package replaces those
// ad-hoc checks with `netip.ParseAddrPort` + `Addr.IsLoopback()`
// which handle every spec-conformant variant.
package netutil

import (
	"errors"
	"net/netip"
	"strings"
)

// ErrEmptyHostPort is returned when an empty string is passed to
// helpers that require a parseable host:port. Callers that want
// to treat empty as a sentinel (e.g. "default to loopback") must
// branch on this explicitly.
var ErrEmptyHostPort = errors.New("netutil: empty host:port")

// IsLoopbackHostPort reports whether a host:port string binds
// only to loopback. Canonical safe-bind detection: when this
// returns true, the operator's `serve` / `proxy listen` runs
// without TLS-warning gate.
//
// Recognised loopback forms:
//
//   - "" (empty) — treated as "default loopback", per the
//     historical cmd_serve.go contract.
//   - localhost:port and localhost (no port).
//   - 127.0.0.1:port, 127.0.0.x:port (any IP in 127/8 — they
//     all loop back per RFC 1122).
//   - [::1]:port — IPv6 loopback shortform.
//   - [0:0:0:0:0:0:0:1]:port — IPv6 loopback longform (rfc 5952
//     §4.2.2 prefers the shortform but the longform is valid).
//   - [::1%zone]:port — IPv6 loopback with interface zone
//     specifier (e.g. `[::1%lo0]` on macOS).
//
// Non-loopback forms (including the IPv6 unspecified address
// `[::]:port` which means "any v6 interface") return false.
func IsLoopbackHostPort(s string) bool {
	if s == "" {
		return true
	}
	// Hostname forms — netip.ParseAddrPort doesn't accept names.
	if isLocalhostName(s) {
		return true
	}
	// Try the full host:port form first.
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr().IsLoopback()
	}
	// Fall back to a bare-address parse (no port) — the operator
	// might be passing just an IP literal without a port.
	if addr, err := netip.ParseAddr(s); err == nil {
		return addr.IsLoopback()
	}
	return false
}

// isLocalhostName matches the `localhost` hostname (with or
// without port). DNS resolution is intentionally NOT performed —
// "localhost" is the bind-time literal we accept; if the
// operator's hosts file resolves localhost to something other
// than 127.0.0.1 / ::1 they can use the explicit IP literal.
func isLocalhostName(s string) bool {
	if s == "localhost" {
		return true
	}
	// "localhost:port" form — must have an exact "localhost"
	// prefix followed by ":" + a port.
	if rest, ok := strings.CutPrefix(s, "localhost:"); ok && rest != "" {
		return true
	}
	return false
}

// CanonicalHostPort normalises a host:port string so that
// equivalent IPv6 forms produce identical output. Specifically:
//
//   - "[::1]:7547" → "[::1]:7547" (canonical; no change).
//   - "[0:0:0:0:0:0:0:1]:7547" → "[::1]:7547" (longform → short).
//   - "[2001:DB8::1]:443" → "[2001:db8::1]:443" (lowercase hex).
//   - "127.0.0.1:7547" → "127.0.0.1:7547" (IPv4 unchanged).
//
// IP-literal canonicalisation matches the rules in RFC 5952
// (the IPv6 address-text representation). Hostname forms are
// returned unchanged (no DNS resolution).
//
// Returns ErrEmptyHostPort when s is empty. Returns the input
// unchanged when it parses as a hostname:port (no IP literal to
// canonicalise).
func CanonicalHostPort(s string) (string, error) {
	if s == "" {
		return "", ErrEmptyHostPort
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		// netip.AddrPort.String() emits the canonical form per
		// RFC 5952 (lowercase, shortest representation) plus
		// brackets around v6 addresses.
		return ap.String(), nil
	}
	// Hostname form (or bare IP without port) — return as-is.
	// CanonicalHostPort doesn't attempt to parse host-only or
	// host-only-with-port; that's beyond IP canonicalisation.
	return s, nil
}

// ParseAddrPort is a thin wrapper around netip.ParseAddrPort
// that returns ErrEmptyHostPort instead of an opaque parser
// error when the input is empty. For non-empty inputs the
// behaviour is identical to netip.ParseAddrPort.
//
// Useful for CLI flag validators that want to distinguish
// "operator omitted the flag" from "operator gave a malformed
// value".
func ParseAddrPort(s string) (netip.AddrPort, error) {
	if s == "" {
		return netip.AddrPort{}, ErrEmptyHostPort
	}
	return netip.ParseAddrPort(s)
}
