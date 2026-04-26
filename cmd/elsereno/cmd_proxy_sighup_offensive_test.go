//go:build offensive

package main

import (
	"errors"
	"strings"
	"testing"
)

// TestErrReloadRequested_Sentinel — pin the contract: the
// errReloadRequested sentinel returned on SIGHUP is a typed,
// non-nil error whose message mentions SIGHUP (so operators
// grepping the proxy log find it). v1.15 chunk 5.
func TestErrReloadRequested_Sentinel(t *testing.T) {
	if errReloadRequested == nil {
		t.Fatal("errReloadRequested should be a typed sentinel, not nil")
	}
	if !errors.Is(errReloadRequested, errReloadRequested) {
		t.Fatal("errors.Is should match the sentinel itself")
	}
	msg := errReloadRequested.Error()
	if msg == "" {
		t.Error("error message is empty")
	}
	if !strings.Contains(msg, "SIGHUP") {
		t.Errorf("error message should mention SIGHUP for operator-grep: %q", msg)
	}
}
