//go:build offensive

package modbus

import (
	"testing"

	mbwire "local/elsereno/internal/protocols/modbus/wire"
)

// TestMatches_ZeroFCNeverWildcard pins L5: a zero-value AllowedWrite
// (and any entry with FC==0) matches no frame, so a blank or
// malformed allowlist row can never turn into a write-everything
// wildcard. A concrete write FC still matches (regression guard).
func TestMatches_ZeroFCNeverWildcard(t *testing.T) {
	f := writeSingleRegister(10, 0x1234)
	if (AllowedWrite{}).Matches(f) {
		t.Fatal("zero-value AllowedWrite must not match any write frame")
	}
	if (AllowedWrite{StartAddr: 0, EndAddr: 0}).Matches(f) {
		t.Fatal("FC=0 with any-address must not match")
	}
	if !(AllowedWrite{FC: mbwire.FCWriteSingleRegister}).Matches(f) {
		t.Fatal("an explicit write FC should still match its frame")
	}
}
