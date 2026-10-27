//go:build offensive

package creds

import (
	"strings"
	"testing"
)

// TestLoadCredsFile_MalformedLineHidesSecret asserts that a malformed
// credential line never appears verbatim in the error (it can reach
// logs or stderr); the 1-based line number is enough to debug (L1).
func TestLoadCredsFile_MalformedLineHidesSecret(t *testing.T) {
	const secret = "supersecret-no-colon-here"
	p := write600(t, "bad.600", "svc:ok\n"+secret+"\n")
	_, err := LoadCredsFile(p)
	if err == nil {
		t.Fatal("expected an error on the malformed line")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaked the credential line: %v", err)
	}
	if !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("error should cite the line number, got: %v", err)
	}
}
