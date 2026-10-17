//go:build mini

package main

import "testing"

// The mini build has no tui --input.
func tuiInputFeedErr(t *testing.T, _, _ string) error {
	t.Helper()
	return nil
}

func tuiAbsent() bool { return true }
