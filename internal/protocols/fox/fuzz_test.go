package fox_test

import (
	"testing"

	"local/elsereno/internal/protocols/fox"
)

// IsFoxBanner classifies a reply the target chose.
func FuzzIsFoxBanner(f *testing.F) {
	f.Add("fox a 0 -1 fox hello\n{\nfox.version=s:1.0\n};;\n")
	f.Add("")
	f.Fuzz(func(_ *testing.T, s string) {
		_ = fox.IsFoxBanner(s)
	})
}
