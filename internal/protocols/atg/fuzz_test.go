package atg_test

import (
	"testing"

	"local/elsereno/internal/protocols/atg"
)

// IsATGResponse classifies a reply the target chose.
func FuzzIsATGResponse(f *testing.F) {
	f.Add("\x01\nI20100\nOCT 21, 2026 10:00 PM\n\nIN-TANK INVENTORY\n")
	f.Add("")
	f.Fuzz(func(_ *testing.T, s string) {
		_ = atg.IsATGResponse(s)
	})
}
