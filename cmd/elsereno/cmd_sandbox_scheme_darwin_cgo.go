//go:build offensive && darwin && cgo

// v2.62 — darwin+cgo scheme accessor for the
// `elsereno sandbox introspect` verb. Routes to the
// sandbox.SchemeFor() helper introduced in v2.61.

package main

import (
	"fmt"

	"local/elsereno/offensive/sandbox"
)

// schemeForProfile returns the live .sb Scheme string for p
// without applying it. (ok=true, scm=<scheme>, nil) on
// recognised profile; (ok=false, "", err) on an unknown
// profile that wasn't caught by Profile.Valid() upstream
// (defensive — collectSchemes filters first).
//
// The third bool from the design sketch is collapsed into
// (ok, error): on this build path, "ok=false" can only mean
// "profile name not found in the scheme map", which is a
// real error rather than the "introspection unavailable"
// signal that the _other.go counterpart emits.
func schemeForProfile(p sandbox.Profile) (string, bool, error) {
	scm, ok := sandbox.SchemeFor(p)
	if !ok {
		return "", false, fmt.Errorf("sandbox: no .sb scheme registered for profile %q (this is an internal bug)", p)
	}
	return scm, true, nil
}

// sandboxIntrospectionAvailable is a const probe used by the
// CLI help text and by tests that want to skip when the
// build doesn't compile the cgo path. True here, false in
// the _other.go counterpart.
const sandboxIntrospectionAvailable = true
