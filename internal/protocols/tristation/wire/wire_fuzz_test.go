package wire

import "testing"

func FuzzParse(f *testing.F) {
	f.Add(BuildConnect())
	f.Add(BuildGetCPStatus(3))
	f.Add([]byte{5, 0, 0xff, 0xff})
	f.Fuzz(func(_ *testing.T, b []byte) {
		_, _ = Parse(b)
		_, _ = ParseCPStatus(b)
	})
}
