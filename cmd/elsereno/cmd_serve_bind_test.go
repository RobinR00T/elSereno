package main

import "testing"

// A non-loopback bind must not serve the API without TLS + the
// explicit flag AND OIDC (the DEV X-Operator identity is spoofable).
func TestValidateBindSecurity(t *testing.T) {
	// Loopback: always fine, OIDC or not.
	if err := validateBindSecurity(serveOpts{addr: "127.0.0.1:8787"}, false); err != nil {
		t.Fatalf("loopback: unexpected error %v", err)
	}
	// Non-loopback missing TLS/flag: rejected even with OIDC.
	if err := validateBindSecurity(serveOpts{addr: "0.0.0.0:8787"}, true); err == nil {
		t.Fatal("non-loopback without tls/flag: want error")
	}
	// Non-loopback with TLS+flag but no OIDC: rejected (fail-open).
	full := serveOpts{addr: "0.0.0.0:8787", tlsCert: "c", tlsKey: "k", iKnow: true}
	if err := validateBindSecurity(full, false); err == nil {
		t.Fatal("non-loopback without OIDC: want error")
	}
	// Non-loopback fully configured: allowed.
	if err := validateBindSecurity(full, true); err != nil {
		t.Fatalf("fully configured: unexpected error %v", err)
	}
}
