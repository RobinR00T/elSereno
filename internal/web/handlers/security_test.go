package handlers

import (
	"strings"
	"testing"
)

// TestBuildControls_NoUnbackedClaims: until 2026-10-16 the security panel
// reported as active controls the binary does not apply: a "Wire-layer
// write-ban" although no command serves the default proxies, a scope that
// checked protocols (nothing calls CheckProtocol) and gated offensive
// writes (no write command loads a scope), a canary webhook nothing
// sends, CSRF protection that does not exist, a redaction hook and a subprocess
// allowlist nothing wires, and a sandbox marked ok in a build that does
// not contain it (PITF-087). Each phrase below is one of those claims.
func TestBuildControls_NoUnbackedClaims(t *testing.T) {
	stale := []string{
		"Wire-layer write-ban",
		"protocol allow/deny +",
		"scope + dial-guard",
		"actively gate writes",
		"Optional HMAC-SHA256",
		"BPF filter sequences ship post-1.0",
		"Bearer tokens only",
	}
	for _, offensive := range []bool{false, true} {
		for _, c := range buildControls(offensive) {
			row := c.Name + " " + c.Detail
			for _, s := range stale {
				if strings.Contains(row, s) {
					t.Errorf("offensive=%v: control %q still claims %q: %s", offensive, c.Name, s, c.Detail)
				}
			}
		}
	}
}

// TestBuildControls_UnwiredControlsAreNotOK: a control that runs only
// when asked (scope) or that no code path uses is "info", never "ok".
func TestBuildControls_UnwiredControlsAreNotOK(t *testing.T) {
	info := []string{"Scope check", "Subprocess allowlist", "Canary webhook"}
	for _, offensive := range []bool{false, true} {
		status := map[string]string{}
		for _, c := range buildControls(offensive) {
			status[c.Name] = c.Status
		}
		for _, name := range info {
			if status[name] != "info" {
				t.Errorf("offensive=%v: %q status = %q, want info", offensive, name, status[name])
			}
		}
		if status["CSRF protection"] != "ok" {
			t.Errorf("offensive=%v: CSRF status = %q, want ok (the browser guard, PITF-092)", offensive, status["CSRF protection"])
		}
		if status["Redaction hook"] != "ok" {
			t.Errorf("offensive=%v: Redaction status = %q, want ok (wired at the log sink, PITF-099)", offensive, status["Redaction hook"])
		}
		if !offensive && status["Offensive sandbox"] != "info" {
			t.Errorf("default build: sandbox status = %q, want info (it is not compiled in)", status["Offensive sandbox"])
		}
	}
}

// TestOverview_NoActiveWriteBanClaim: the dashboard said the write-ban
// "applies to every TCP plugin"; no command serves those proxies.
func TestOverview_NoActiveWriteBanClaim(t *testing.T) {
	if strings.Contains(overviewHTML, "applies to every TCP plugin") {
		t.Fatal("the dashboard still claims an active wire-layer write-ban")
	}
}
