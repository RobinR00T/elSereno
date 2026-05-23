//go:build offensive && (!darwin || !cgo)

// v2.62 — non-darwin / non-cgo stub for the
// `elsereno sandbox introspect` verb. The .sb Scheme strings
// only exist on the darwin+cgo build (the cgo wrapper file
// itself doesn't compile elsewhere). This file returns
// (ok=false, "", nil) so the dispatcher emits a sentinel
// "introspection not supported" entry rather than a hard
// error — the verb is still useful for piping through `jq`
// when you want a stable JSON shape across builds.

package main

import (
	"local/elsereno/offensive/sandbox"
)

// schemeForProfile is the platform-stub. ok=false signals
// "introspection unavailable on this build" — the
// dispatcher (cmd_sandbox_offensive.go) translates it into
// a sandboxSchemeResult{Profile: <name>, Scheme: ""} entry.
func schemeForProfile(_ sandbox.Profile) (string, bool, error) {
	return "", false, nil
}

// sandboxIntrospectionAvailable is false here so tests +
// help text can branch off the const.
const sandboxIntrospectionAvailable = false
